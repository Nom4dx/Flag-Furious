"""Safe ZIP inventory/extraction with anti-bomb and path controls."""

from __future__ import annotations

import io
import stat
import zipfile
from pathlib import Path, PurePosixPath

from .artifact_store import ArtifactStore


def _unsafe_name(name: str) -> bool:
    """Reject absolute paths, traversal, NUL and drive-style member names."""
    pure = PurePosixPath(name.replace("\\", "/"))
    return "\x00" in name or pure.is_absolute() or ".." in pure.parts or (len(name) > 1 and name[1] == ":")


def analyze_zip(path: Path, boundary: dict, store: ArtifactStore, limits: dict) -> dict:
    """Inventory and safely extract regular ZIP members without executing them.

    The central directory was validated before entry. Zip Slip, symlinks,
    per-member size, total expansion and compression-ratio limits are enforced.
    CRC failures make a member a warning and never a trusted artifact.
    """
    with path.open("rb") as stream:
        stream.seek(boundary["start_offset"]); raw = stream.read(boundary["length"])
    entries, artifacts, warnings, total = [], [], [], 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for info in archive.infolist()[:limits["max_entries"]]:
            mode = (info.external_attr >> 16) & 0xFFFF
            ratio = info.file_size / max(1, info.compress_size)
            safe = not _unsafe_name(info.filename) and not stat.S_ISLNK(mode) and not info.is_dir()
            reason = None
            if info.flag_bits & 1: reason = "entry cifrata: password non disponibile"
            elif _unsafe_name(info.filename): reason = "path traversal"
            elif stat.S_ISLNK(mode): reason = "symlink"
            elif ratio > limits["max_ratio"]: reason = "rapporto di espansione oltre il limite"
            elif info.file_size > limits["max_member_bytes"]: reason = "entry oltre il limite"
            elif total + info.file_size > limits["max_total_bytes"]: reason = "budget di espansione esaurito"
            record = {"name": info.filename, "size": info.file_size, "compressed_size": info.compress_size, "crc32": f"{info.CRC:08x}", "ratio": round(ratio, 2), "safe_to_extract": safe and reason is None, "rejection_reason": reason}
            entries.append(record)
            if reason:
                warnings.append(f"ZIP {info.filename}: {reason}"); continue
            if not safe:
                continue
            try:
                data = archive.read(info)
                total += len(data)
                artifact = store.save_bytes("embedded", info.filename, data, {
                    "format": "zip_entry", "internal_path": info.filename, "source_offset": boundary["start_offset"],
                    "extraction_method": "zip_central_directory", "parent_format_id": boundary["id"], "confidence": .99,
                })
                artifacts.append(artifact)
            except (RuntimeError, zipfile.BadZipFile, ValueError, OSError) as exc:
                warnings.append(f"ZIP {info.filename}: {exc}")
    return {"format_id": boundary["id"], "entries": entries, "artifacts": artifacts, "warnings": warnings, "extracted_bytes": total}


def recover_zip_local_headers(path: Path, candidate: dict, max_bytes: int, max_entries: int = 128) -> dict:
    """Inventory local ZIP headers when the central directory is damaged.

    Results are explicitly partial and never extracted or presented as validated.
    Declared fields must remain inside the bounded view. Data descriptors stop
    sequential recovery rather than causing boundary guesses.
    """
    import struct
    start = candidate["offset"]
    with path.open("rb") as stream:
        stream.seek(start); data = stream.read(max_bytes)
    entries, cursor = [], 0
    while len(entries) < max_entries:
        pos = data.find(b"PK\x03\x04", cursor)
        if pos < 0 or pos + 30 > len(data): break
        fields = struct.unpack("<4s5H3L2H", data[pos:pos + 30])
        flags, method = fields[2], fields[3]
        crc, compressed, uncompressed = fields[6], fields[7], fields[8]
        name_len, extra_len = fields[9], fields[10]
        header_end = pos + 30 + name_len + extra_len
        if not name_len or header_end > len(data) or compressed > max_bytes or header_end + compressed > len(data):
            cursor = pos + 4; continue
        name = data[pos + 30:pos + 30 + name_len].decode("utf-8", "replace")
        entries.append({"name": name, "offset": start + pos, "compressed_size": compressed, "size": uncompressed, "crc32_declared": f"{crc:08x}", "method": method, "data_descriptor": bool(flags & 8), "validated": False, "confidence": .45})
        cursor = header_end + compressed if not flags & 8 else pos + 4
    return {"mode": "local_header_recovery", "candidate_offset": start, "validated": False, "status": "partial", "entries": entries, "warning": "Central directory non valida: entry recuperate solo come candidate"}
