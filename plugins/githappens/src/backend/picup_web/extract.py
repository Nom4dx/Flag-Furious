from __future__ import annotations

import gzip
import lzma
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Callable

from .util import inside, safe_name

MAX_FILES = 5_000
MAX_MEMBER = 64 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_DEPTH = 5
MAX_COMPRESSION_RATIO = 200
CHUNK = 1024 * 1024


def _target(root: Path, relative: str, index: int) -> Path:
    parts = [safe_name(part) for part in relative.replace("\\", "/").split("/") if part not in ("", ".", "..")]
    target = root.joinpath(*parts) if parts else root / f"member_{index}"
    target.parent.mkdir(parents=True, exist_ok=True)
    target = inside(root, target)
    if target.exists():
        target = target.with_name(f"{target.stem}_{index}{target.suffix}")
    return target


def _copy_bounded(source: BinaryIO, target: Path, limit: int) -> tuple[int, bool]:
    written = 0
    with target.open("xb") as destination:
        while block := source.read(min(CHUNK, limit - written + 1)):
            if written + len(block) > limit:
                return written, True
            destination.write(block)
            written += len(block)
    return written, False


def extract_recursive(seed: Path, output: Path, *, depth: int = 0,
                      max_bytes: int = MAX_TOTAL) -> tuple[list[Path], list[str]]:
    """Extract containers incrementally with one cumulative recursive budget."""
    output.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []
    warnings: list[str] = []
    byte_limit = min(MAX_TOTAL, max(0, int(max_bytes)))
    bytes_written = 0
    queue: list[tuple[Path, int]] = [(seed, depth)]
    while queue:
        if len(extracted) >= MAX_FILES:
            warnings.append(f"Inventario derivati limitato a {MAX_FILES} file")
            break
        source, level = queue.pop(0)
        if level >= MAX_DEPTH:
            continue
        source_size = max(1, source.stat().st_size)
        container_root = output / f"level_{level + 1}_{safe_name(source.stem)}_{len(extracted)}"
        partial_target: Path | None = None
        try:
            suffix = source.suffix.casefold()
            if suffix in {".gz", ".xz"}:
                opener = gzip.open if suffix == ".gz" else lzma.open
                target = _target(container_root, source.stem, len(extracted))
                partial_target = target
                remaining = min(MAX_MEMBER, byte_limit - bytes_written, source_size * MAX_COMPRESSION_RATIO)
                with opener(source, "rb") as handle:
                    count, truncated = _copy_bounded(handle, target, remaining)
                if truncated:
                    target.unlink(missing_ok=True)
                    partial_target = None
                    warnings.append(f"{source.name}: output compresso oltre il budget, derivato saltato")
                    continue
                bytes_written += count
                extracted.append(target)
                partial_target = None
                queue.append((target, level + 1))
                continue

            if zipfile.is_zipfile(source):
                with zipfile.ZipFile(source) as archive:
                    for index, info in enumerate(archive.infolist()):
                        if len(extracted) >= MAX_FILES or bytes_written >= byte_limit:
                            warnings.append("Budget cumulativo di file/byte raggiunto durante estrazione ZIP")
                            break
                        mode = info.external_attr >> 16
                        name = PurePosixPath(info.filename.replace("\\", "/"))
                        if info.is_dir():
                            continue
                        if name.is_absolute() or ".." in name.parts or stat.S_ISLNK(mode):
                            warnings.append(f"{info.filename}: membro con path o symlink non sicuro")
                            continue
                        remaining = min(MAX_MEMBER, byte_limit - bytes_written)
                        if info.file_size > remaining or info.file_size > MAX_MEMBER:
                            warnings.append(f"{info.filename}: membro oltre il budget, saltato")
                            continue
                        if info.file_size / max(1, info.compress_size) > MAX_COMPRESSION_RATIO:
                            warnings.append(f"{info.filename}: rapporto di compressione oltre il limite")
                            continue
                        target = _target(container_root, info.filename, index)
                        partial_target = target
                        with archive.open(info) as handle:
                            count, truncated = _copy_bounded(handle, target, remaining)
                        if truncated or count != info.file_size:
                            target.unlink(missing_ok=True)
                            partial_target = None
                            warnings.append(f"{info.filename}: dimensione/CRC non coerente, derivato saltato")
                            continue
                        bytes_written += count
                        extracted.append(target)
                        partial_target = None
                        queue.append((target, level + 1))
                continue

            if tarfile.is_tarfile(source):
                with tarfile.open(source, "r:*") as archive:
                    for index, info in enumerate(archive):
                        if len(extracted) >= MAX_FILES or bytes_written >= byte_limit:
                            warnings.append("Budget cumulativo di file/byte raggiunto durante estrazione TAR")
                            break
                        name = PurePosixPath(info.name.replace("\\", "/"))
                        if not info.isfile():
                            continue
                        if name.is_absolute() or ".." in name.parts:
                            warnings.append(f"{info.name}: membro con path non sicuro")
                            continue
                        remaining = min(MAX_MEMBER, byte_limit - bytes_written)
                        if info.size > remaining or info.size > MAX_MEMBER:
                            warnings.append(f"{info.name}: membro oltre il budget, saltato")
                            continue
                        handle = archive.extractfile(info)
                        if handle is None:
                            continue
                        target = _target(container_root, info.name, index)
                        partial_target = target
                        with handle:
                            count, truncated = _copy_bounded(handle, target, remaining)
                        if truncated or count != info.size:
                            target.unlink(missing_ok=True)
                            partial_target = None
                            warnings.append(f"{info.name}: dimensione non coerente, derivato saltato")
                            continue
                        bytes_written += count
                        extracted.append(target)
                        partial_target = None
                        queue.append((target, level + 1))
        except (OSError, EOFError, ValueError, tarfile.TarError, zipfile.BadZipFile, lzma.LZMAError) as exc:
            if partial_target is not None:
                partial_target.unlink(missing_ok=True)
            warnings.append(f"Estrazione {source.name} incompleta: {exc}")
    return extracted, warnings
