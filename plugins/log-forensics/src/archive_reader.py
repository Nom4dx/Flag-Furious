"""Bounded reader for log directories, rotations and compressed containers."""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import stat
import zipfile
from pathlib import Path, PurePosixPath


MAX_WALK_DIRS = 10_000


def _files(path: Path, maximum: int):
    """Return a deterministic bounded file set without following symlinks."""
    if path.is_file() and not path.is_symlink():
        return [path], False
    paths = []
    scanned_dirs = 0
    for root, dirs, files in os.walk(path, followlinks=False):
        scanned_dirs += 1
        if scanned_dirs > MAX_WALK_DIRS:
            return paths, True
        dirs[:] = sorted(name for name in dirs if not (Path(root) / name).is_symlink())
        for name in sorted(files):
            candidate = Path(root) / name
            if candidate.is_symlink() or not candidate.is_file():
                continue
            if len(paths) >= maximum:
                return paths, True
            paths.append(candidate)
    return paths, False


def _read_prefix(path: Path, limit: int) -> bytes:
    with path.open("rb") as source:
        return source.read(max(0, limit))


def _decompress(raw: bytes, suffix: str, limit: int):
    """Return a capped decompressed prefix and whether expansion was capped."""
    maximum = max(0, limit)
    if raw.startswith(b"\x1f\x8b") or suffix == ".gz":
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as decoder:
            data = decoder.read(maximum + 1)
            return data[:maximum], len(data) > maximum
    if raw.startswith(b"BZh") or suffix == ".bz2":
        decoder = bz2.BZ2Decompressor()
        data = decoder.decompress(raw, max_length=maximum + 1)
        return data[:maximum], len(data) > maximum or not decoder.eof
    decoder = lzma.LZMADecompressor()
    data = decoder.decompress(raw, max_length=maximum + 1)
    return data[:maximum], len(data) > maximum or not decoder.eof


def collect(path: Path, budget: int, store, max_files: int = 256,
            max_single: int = 64 * 1024**2, max_ratio: int = 100):
    """Return bounded in-memory sources, derived artifacts and coverage warnings."""
    sources, artifacts, warnings = [], [], []
    remaining = max(0, int(budget))
    expanded_remaining = min(remaining, 256 * 1024**2)
    maximum_files = max(1, min(int(max_files), 1024))
    paths, discovery_limited = _files(path, maximum_files)
    if not paths:
        warnings.append("Nessun file regolare disponibile nella vista di input")
    if discovery_limited:
        warnings.append(f"Inventario limitato a {maximum_files} file o {MAX_WALK_DIRS} directory")

    for item in paths:
        if remaining <= 0:
            warnings.append("Byte budget raggiunto durante la lettura sorgenti")
            break
        source_name = str(item.relative_to(path)) if path.is_dir() else item.name
        try:
            physical_size = item.stat().st_size
            if physical_size > max_single and item.suffix.casefold() in {".zip", ".gz", ".bz2", ".xz"}:
                warnings.append(f"{item.name}: contenitore oltre il limite di input {max_single} byte")
                continue
            raw = _read_prefix(item, min(remaining, max_single))
        except OSError as exc:
            warnings.append(f"{item.name}: {exc}")
            continue
        remaining -= len(raw)
        if len(raw) < physical_size:
            warnings.append(f"{item.name}: vista limitata a {len(raw)} di {physical_size} byte")

        suffix = item.suffix.casefold()
        is_compressed = suffix in {".gz", ".bz2", ".xz"} or raw.startswith((b"\x1f\x8b\x08", b"BZh", b"\xfd7zXZ\x00"))
        try:
            if is_compressed:
                expansion_cap = min(max_single, expanded_remaining, max(1, len(raw)) * max_ratio)
                decoded, capped = _decompress(raw, suffix, expansion_cap)
                expanded_remaining -= len(decoded)
                try:
                    artifact = store.save("decompressed", item.stem or "log", decoded,
                                          {"source_file": source_name, "extraction_method": "bounded_decompression",
                                           "detected_type": "log_candidate", "complete": not capped})
                    artifacts.append(artifact)
                    source_path = Path(artifact["path"])
                except ValueError as exc:
                    warnings.append(str(exc))
                    source_path = None
                sources.append((source_name, decoded, source_path))
                if capped:
                    warnings.append(f"{item.name}: decompressione parziale entro il limite di espansione")
                continue

            if suffix == ".zip" or raw.startswith(b"PK\x03\x04"):
                if len(raw) < physical_size:
                    warnings.append(f"{item.name}: ZIP non aperto perché la vista del contenitore è parziale")
                    continue
                with zipfile.ZipFile(item) as archive:
                    members = archive.infolist()
                    if len(members) > maximum_files:
                        warnings.append(f"{item.name}: inventario ZIP limitato a {maximum_files} membri")
                    for member in members[:maximum_files]:
                        name = PurePosixPath(member.filename.replace("\\", "/"))
                        link = stat.S_ISLNK(member.external_attr >> 16)
                        if member.is_dir():
                            continue
                        if member.flag_bits & 1:
                            warnings.append(f"{member.filename}: membro cifrato non estratto")
                            continue
                        if name.is_absolute() or ".." in name.parts or link:
                            warnings.append(f"{member.filename}: path o symlink non sicuro")
                            continue
                        ratio = member.file_size / max(1, member.compress_size)
                        cap = min(max_single, expanded_remaining, member.file_size)
                        if member.file_size > cap or ratio > max_ratio:
                            warnings.append(f"{member.filename}: limite dimensione o rapporto di espansione")
                            continue
                        with archive.open(member) as stream:
                            decoded = stream.read(cap + 1)
                        if len(decoded) > cap:
                            warnings.append(f"{member.filename}: estrazione troncata al budget")
                            decoded = decoded[:cap]
                        expanded_remaining -= len(decoded)
                        artifact = store.save("archive", name.name, decoded,
                                              {"source_file": source_name, "internal_path": member.filename,
                                               "extraction_method": "zip_crc", "detected_type": "log_candidate",
                                               "complete": len(decoded) == member.file_size})
                        artifacts.append(artifact)
                        sources.append((member.filename, decoded, Path(artifact["path"])))
                        if expanded_remaining <= 0:
                            warnings.append("Budget cumulativo di espansione raggiunto")
                            break
                continue
            sources.append((source_name, raw, item))
        except (OSError, ValueError, EOFError, zipfile.BadZipFile, lzma.LZMAError, RuntimeError) as exc:
            warnings.append(f"{item.name}: contenitore non estratto: {str(exc)[:240]}")

    return sources, artifacts, warnings, budget - remaining
