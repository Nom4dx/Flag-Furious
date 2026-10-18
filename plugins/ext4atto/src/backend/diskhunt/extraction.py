from __future__ import annotations
import gzip
import lzma
import shutil
import subprocess
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from .artifacts import ArtifactCatalog, detect_mime
from .security import safe_filename


@dataclass
class ExtractionLimits:
    max_depth: int = 4
    max_files: int = 1000
    max_total_bytes: int = 256 * 1024 * 1024
    max_file_bytes: int = 64 * 1024 * 1024
    max_ratio: int = 200


class RecursiveExtractor:
    def __init__(self, catalog: ArtifactCatalog, output: Path, limits: ExtractionLimits | None = None):
        self.catalog = catalog; self.output = output; self.limits = limits or ExtractionLimits()
        self.files = 0; self.total = 0; self.warnings: list[str] = []

    def expand(self, record: dict, depth: int = 0) -> list[dict]:
        if depth >= self.limits.max_depth: return []
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
            if not child or not child.is_file(): continue
            child_record = self.catalog.register(child, name_original=child.name, original_path=record.get("original_path", ""),
                method="recursive extraction", status="VISIBLE", confidence=90, parent_artifact=record["artifact"],
                partition=record.get("partition"), filesystem=record.get("filesystem"), inode=record.get("inode"), depth=depth + 1)
            records.append(child_record); records.extend(self.expand(child_record, depth + 1))
        return records

    def _accept(self, size: int, compressed: int = 0):
        if self.files + 1 > self.limits.max_files: raise ValueError("archive file-count limit exceeded")
        if size > self.limits.max_file_bytes or self.total + size > self.limits.max_total_bytes: raise ValueError("archive expansion byte limit exceeded")
        if compressed and size / max(1, compressed) > self.limits.max_ratio: raise ValueError("suspicious compression ratio")
        self.files += 1; self.total += size

    def _safe_target(self, root: Path, name: str) -> Path:
        pure = PurePosixPath(name.replace("\\", "/"))
        if pure.is_absolute() or ".." in pure.parts: raise ValueError("archive path traversal rejected")
        parts = [safe_filename(part, "item") for part in pure.parts if part not in {"", "."}]
        target = root.joinpath(*parts).resolve()
        if root.resolve() not in target.parents: raise ValueError("archive path escapes extraction root")
        return target

    def _zip(self, source: Path, target_dir: Path) -> list[Path]:
        result = []
        with zipfile.ZipFile(source) as archive:
            for info in archive.infolist():
                if info.is_dir(): continue
                self._accept(info.file_size, info.compress_size); target = self._safe_target(target_dir, info.filename)
                target.parent.mkdir(parents=True, exist_ok=True)
                if not target.exists():
                    with archive.open(info) as src, target.open("xb") as dst: self._copy_limited(src, dst, info.file_size)
                result.append(target)
        return result

    def _tar(self, source: Path, target_dir: Path) -> list[Path]:
        result = []
        with tarfile.open(source, "r:*") as archive:
            for member in archive:
                if not member.isfile(): continue
                self._accept(member.size); target = self._safe_target(target_dir, member.name); target.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                if stream:
                    if not target.exists():
                        with stream, target.open("xb") as dst: self._copy_limited(stream, dst, member.size)
                    result.append(target)
        return result

    def _stream(self, opener, source: Path, target: Path) -> Path:
        if target.exists(): return target
        with opener(source, "rb") as src, target.open("xb") as dst:
            written = self._copy_limited(src, dst, self.limits.max_file_bytes)
        self._accept(written, source.stat().st_size); return target

    def _copy_limited(self, src, dst, declared: int) -> int:
        written = 0
        while block := src.read(min(1024 * 1024, self.limits.max_file_bytes - written + 1)):
            written += len(block)
            if written > self.limits.max_file_bytes: raise ValueError("expanded file exceeds limit")
            dst.write(block)
        return written

    def _seven_zip(self, source: Path, target_dir: Path) -> list[Path]:
        binary = shutil.which("7z") or shutil.which("7zz")
        if not binary: self.warnings.append(f"7z/rar extractor unavailable for {source.name}"); return []
        listing = subprocess.run([binary, "l", "-slt", "--", str(source)], capture_output=True, text=True, timeout=30)
        names = [line[7:] for line in listing.stdout.splitlines() if line.startswith("Path = ")][1:]
        for name in names: self._safe_target(target_dir, name)
        proc = subprocess.run([binary, "x", "-y", f"-o{target_dir}", "--", str(source)], capture_output=True, timeout=120)
        if proc.returncode: raise ValueError("7z extraction failed")
        result = [path for path in target_dir.rglob("*") if path.is_file()]
        for path in result: self._accept(path.stat().st_size)
        return result

    def _pdf_text(self, source: Path, target_dir: Path) -> list[Path]:
        binary = shutil.which("pdftotext")
        if not binary: return []
        target = target_dir / f"{safe_filename(source.stem)}.txt"
        proc = subprocess.run([binary, "-q", "-nopgbrk", str(source), str(target)], capture_output=True, timeout=60)
        if proc.returncode or not target.exists(): return []
        self._accept(target.stat().st_size); return [target]
