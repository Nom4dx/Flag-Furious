from __future__ import annotations

import gzip
import io
import lzma
import shutil
import tarfile
import zipfile
from pathlib import Path

from .util import inside, safe_name

MAX_FILES = 10_000
MAX_MEMBER = 256 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_DEPTH = 5
MAX_DISK_IMAGE = 8 * 1024 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200


def _target(root: Path, relative: str, index: int) -> Path:
    parts = [safe_name(part) for part in relative.replace("\\", "/").split("/") if part not in ("", ".", "..")]
    target = root.joinpath(*parts) if parts else root / f"member_{index}"
    target.parent.mkdir(parents=True, exist_ok=True)
    return inside(root, target)


def extract_recursive(seed: Path, output: Path, *, depth: int = 0) -> tuple[list[Path], list[str]]:
    """Extract common containers with traversal and decompression-bomb limits."""
    output.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []
    warnings: list[str] = []
    total = 0
    queue: list[tuple[Path, int]] = [(seed, depth)]
    while queue and len(extracted) < MAX_FILES:
        source, level = queue.pop(0)
        stream_target: Path | None = None
        if level >= MAX_DEPTH:
            continue
        members: list[tuple[str, bytes]] = []
        try:
            if source.suffix.lower() in (".gz", ".xz"):
                opener = gzip.open if source.suffix.lower() == ".gz" else lzma.open
                target = _target(output / f"level_{level + 1}_{safe_name(source.stem)}", source.stem, 0)
                if target.exists():
                    target = target.with_name(target.name + f"_{len(extracted)}")
                stream_target = target
                written = 0
                with opener(source, "rb") as handle, target.open("xb") as destination:
                    while block := handle.read(4 * 1024 * 1024):
                        written += len(block)
                        if written > MAX_DISK_IMAGE or written > max(source.stat().st_size, 1) * MAX_COMPRESSION_RATIO:
                            raise ValueError("compressed stream exceeds image/ratio safety limit")
                        destination.write(block)
                total += written
                extracted.append(target)
                queue.append((target, level + 1))
                continue
            if zipfile.is_zipfile(source):
                with zipfile.ZipFile(source) as archive:
                    for info in archive.infolist():
                        if info.is_dir() or info.file_size > MAX_MEMBER:
                            continue
                        members.append((info.filename, archive.read(info)))
            elif tarfile.is_tarfile(source):
                with tarfile.open(source, "r:*") as archive:
                    for info in archive.getmembers():
                        if not info.isfile() or info.size > MAX_MEMBER:
                            continue
                        handle = archive.extractfile(info)
                        if handle:
                            members.append((info.name, handle.read(MAX_MEMBER + 1)))
        except Exception as exc:
            if stream_target is not None:
                stream_target.unlink(missing_ok=True)
            warnings.append(f"Cannot extract {source.name}: {exc}")
        for index, (name, data) in enumerate(members):
            if len(data) > MAX_MEMBER or total + len(data) > MAX_TOTAL:
                warnings.append(f"Extraction safety limit reached at {name}")
                return extracted, warnings
            target = _target(output / f"level_{level + 1}_{safe_name(source.stem)}", name, index)
            if target.exists():
                target = target.with_name(f"{target.stem}_{index}{target.suffix}")
            target.write_bytes(data)
            total += len(data)
            extracted.append(target)
            queue.append((target, level + 1))
    return extracted, warnings
