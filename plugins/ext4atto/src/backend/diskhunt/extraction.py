from __future__ import annotations
import gzip
import lzma
import re
import shutil
import tarfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from .artifacts import ArtifactCatalog, detect_mime
from .security import safe_filename
from .bounded_process import run_bounded


@dataclass
class ExtractionLimits:
    max_depth: int = 4
    max_files: int = 1000
    max_total_bytes: int = 256 * 1024 * 1024
    max_file_bytes: int = 64 * 1024 * 1024
    max_ratio: int = 200
    max_seconds: int = 300


class RecursiveExtractor:
    def __init__(self, catalog: ArtifactCatalog, output: Path, limits: ExtractionLimits | None = None):
        self.catalog = catalog; self.output = output; self.limits = limits or ExtractionLimits()
        self.files = 0; self.total = 0; self.warnings: list[str] = []; self.started = time.monotonic(); self.time_warning = False

    def _remaining_seconds(self) -> float:
        return self.limits.max_seconds - (time.monotonic() - self.started)

    def _time_available(self) -> bool:
        if self._remaining_seconds() > 0:
            return True
        if not self.time_warning:
            self.warnings.append(f"Recursive extraction stopped at the {self.limits.max_seconds}s time limit")
            self.time_warning = True
        return False

    def expand(self, record: dict, depth: int = 0) -> list[dict]:
        if depth >= self.limits.max_depth or not self._time_available(): return []
        source = self.catalog.root / record["artifact"]; mime = record["mime_type"]
        target_dir = self.output / record["sha256"][:16]
        target_dir.mkdir(parents=True, exist_ok=True); children: list[Path] = []
        try:
            if mime == "application/zip": children = self._zip(source, target_dir)
            elif mime in {"application/gzip", "application/x-gzip"}: children = [self._stream(gzip.open, source, target_dir / safe_filename(source.stem))]
            elif mime in {"application/x-xz", "application/x-lzma"}: children = [self._stream(lzma.open, source, target_dir / safe_filename(source.stem))]
            elif tarfile.is_tarfile(source): children = self._tar(source, target_dir)
            elif mime in {"application/x-7z-compressed", "application/vnd.rar"}: children = self._seven_zip(source, target_dir)
            elif mime == "application/pdf": children = self._pdf_text(source, target_dir)
        except (OSError, ValueError, EOFError, zipfile.BadZipFile, tarfile.TarError) as exc:
            self.warnings.append(f"cannot extract {record['artifact']}: {exc}"); return []
        records = []
        for child in children:
            if not self._time_available(): break
            if not child or not child.is_file(): continue
            child_record = self.catalog.register(child, name_original=child.name, original_path=record.get("original_path", ""),
                method="recursive extraction", status="VISIBLE", confidence=90, parent_artifact=record["artifact"],
                partition=record.get("partition"), filesystem=record.get("filesystem"), inode=record.get("inode"), depth=depth + 1)
            records.append(child_record); records.extend(self.expand(child_record, depth + 1))
        return records

    def _check(self, size: int, compressed: int = 0):
        if self.files + 1 > self.limits.max_files: raise ValueError("archive file-count limit exceeded")
        if size > self.limits.max_file_bytes or self.total + size > self.limits.max_total_bytes: raise ValueError("archive expansion byte limit exceeded")
        if compressed and size / max(1, compressed) > self.limits.max_ratio: raise ValueError("suspicious compression ratio")

    def _accept(self, size: int, compressed: int = 0):
        self._check(size, compressed)
        self.files += 1; self.total += size

    def _safe_target(self, root: Path, name: str) -> Path:
        pure = PurePosixPath(name.replace("\\", "/"))
        if pure.is_absolute() or ".." in pure.parts: raise ValueError("archive path traversal rejected")
        parts = [safe_filename(part, "item") for part in pure.parts if part not in {"", "."}]
        target = root.joinpath(*parts).resolve()
        if root.resolve() not in target.parents: raise ValueError("archive path escapes extraction root")
        if target.exists():
            original = target
            index = 1
            while target.exists():
                target = original.with_name(f"{original.stem}_{index}{original.suffix}")
                index += 1
        return target

    def _zip(self, source: Path, target_dir: Path) -> list[Path]:
        result = []
        with zipfile.ZipFile(source) as archive:
            for info in archive.infolist():
                if not self._time_available(): break
                if info.is_dir(): continue
                mode = info.external_attr >> 16
                if (mode & 0o170000) == 0o120000:
                    self.warnings.append(f"{info.filename}: symbolic link skipped")
                    continue
                self._check(info.file_size, info.compress_size); target = self._safe_target(target_dir, info.filename)
                target.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with archive.open(info) as src, target.open("xb") as dst: written = self._copy_limited(src, dst, info.file_size)
                    if written != info.file_size: raise ValueError("ZIP member size mismatch")
                except Exception:
                    target.unlink(missing_ok=True)
                    raise
                self._accept(written, info.compress_size)
                result.append(target)
        return result

    def _tar(self, source: Path, target_dir: Path) -> list[Path]:
        result = []
        with tarfile.open(source, "r:*") as archive:
            for member in archive:
                if not self._time_available(): break
                if not member.isfile(): continue
                self._check(member.size); target = self._safe_target(target_dir, member.name); target.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                if stream:
                    try:
                        with stream, target.open("xb") as dst: written = self._copy_limited(stream, dst, member.size)
                        if written != member.size: raise ValueError("TAR member size mismatch")
                    except Exception:
                        target.unlink(missing_ok=True)
                        raise
                    self._accept(written)
                    result.append(target)
        return result

    def _stream(self, opener, source: Path, target: Path) -> Path:
        if target.exists(): return target
        remaining = min(self.limits.max_file_bytes, self.limits.max_total_bytes - self.total)
        try:
            with opener(source, "rb") as src, target.open("xb") as dst:
                written = self._copy_limited(src, dst, remaining)
            self._accept(written, source.stat().st_size)
            return target
        except Exception:
            target.unlink(missing_ok=True)
            raise

    def _copy_limited(self, src, dst, declared: int) -> int:
        written = 0
        while block := src.read(min(1024 * 1024, self.limits.max_file_bytes - written + 1)):
            written += len(block)
            if written > min(self.limits.max_file_bytes, declared): raise ValueError("expanded file exceeds limit")
            dst.write(block)
        return written

    def _seven_zip(self, source: Path, target_dir: Path) -> list[Path]:
        binary = shutil.which("7z") or shutil.which("7zz")
        if not binary: self.warnings.append(f"7z/rar extractor unavailable for {source.name}"); return []
        if not self._time_available(): return []
        listing = run_bounded([binary, "l", "-slt", "--", str(source)], timeout=max(1, min(30, int(self._remaining_seconds()))), max_stdout=8 * 1024 * 1024)
        if listing["timed_out"]:
            self.warnings.append(f"7z listing timeout: {source.name}")
            return []
        if listing["returncode"] != 0:
            self.warnings.append(f"7z listing returned {listing['returncode']}: {source.name}")
        if listing["truncated"]:
            self.warnings.append(f"7z listing troncato: {source.name}; inventario parziale")
        entries = []
        for block in re.split(r"\r?\n\r?\n", listing["stdout"].decode("utf-8", "replace")):
            fields = dict(line.split(" = ", 1) for line in block.splitlines() if " = " in line)
            name = fields.get("Path")
            if not name or "Type" in fields or fields.get("Folder") == "+": continue
            try:
                size = int(fields["Size"]); packed = int(fields.get("Packed Size", "0"))
            except (KeyError, ValueError):
                self.warnings.append(f"7z member senza dimensione valida in {source.name}")
                continue
            entries.append((name, size, packed))
            if len(entries) >= self.limits.max_files - self.files:
                self.warnings.append("7z member inventory limit reached")
                break
        result = []
        for name, size, packed in entries:
            if not self._time_available(): break
            try:
                self._check(size, packed)
                target = self._safe_target(target_dir, name)
                target.parent.mkdir(parents=True, exist_ok=True)
                proc = run_bounded([binary, "x", "-so", "--", str(source), name], timeout=max(1, min(120, int(self._remaining_seconds()))),
                                   max_stdout=min(self.limits.max_file_bytes, self.limits.max_total_bytes-self.total),
                                   output_path=target)
                actual = target.stat().st_size if target.exists() else 0
                if proc["stderr_truncated"]:
                    self.warnings.append(f"7z diagnostics truncated: {name}")
                if proc["timed_out"] or proc["truncated"] or proc["returncode"] != 0 or actual != size:
                    target.unlink(missing_ok=True)
                    self.warnings.append(f"7z member extraction incomplete: {name}")
                    continue
                self._accept(actual, packed)
                result.append(target)
            except (OSError, ValueError) as exc:
                self.warnings.append(f"7z member skipped {name}: {exc}")
        return result

    def _pdf_text(self, source: Path, target_dir: Path) -> list[Path]:
        binary = shutil.which("pdftotext")
        if not binary: return []
        target = target_dir / f"{safe_filename(source.stem)}.txt"
        if not self._time_available(): return []
        proc = run_bounded([binary, "-q", "-nopgbrk", str(source), "-"], timeout=max(1, min(60, int(self._remaining_seconds()))),
                           max_stdout=min(self.limits.max_file_bytes, self.limits.max_total_bytes-self.total),
                           output_path=target)
        if proc["stderr_truncated"]:
            self.warnings.append(f"PDF text diagnostics truncated: {source.name}")
        if proc["returncode"] or proc["timed_out"] or proc["truncated"] or not target.exists():
            target.unlink(missing_ok=True)
            self.warnings.append(f"PDF text extraction incomplete: {source.name}")
            return []
        self._accept(target.stat().st_size); return [target]
