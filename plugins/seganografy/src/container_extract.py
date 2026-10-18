"""Safe artifact storage and ZIP/document container extraction.

Only regular members referenced by the central directory are extracted. Zip
Slip, symlinks, encryption, per-file limits and archive bombs are reported rather
than bypassed.
"""

from __future__ import annotations

import hashlib
import io
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath

from .limits import Limits


class ArtifactStore:
    """Write deduplicated passive artifacts inside the worker output directory."""

    def __init__(self, root: Path, limits: Limits):
        self.root = root
        self.limits = limits
        self.written = 0
        self.index: dict[str, dict] = {}

    def save(self, category: str, name: str, data: bytes, metadata: dict | None = None) -> dict:
        """Save bytes with a safe name and return provenance metadata.

        Raises ``ValueError`` on configured size/output limits. Identical SHA-256
        content returns the prior path with ``deduplicated`` set. No symlink or
        user-controlled directory is created.
        """
        if len(data) > self.limits.max_single_artifact_size:
            raise ValueError("artefatto oltre max_single_artifact_size")
        digest = hashlib.sha256(data).hexdigest()
        if digest in self.index:
            return {**self.index[digest], "deduplicated": True}
        if self.written + len(data) > self.limits.output_budget:
            raise ValueError("max_total_output_size raggiunto")
        folder = self.root / (re.sub(r"[^a-z0-9_-]", "_", category.lower()) or "raw")
        folder.mkdir(parents=True, exist_ok=True)
        clean = re.sub(r"[^A-Za-z0-9._-]", "_", Path(name).name).strip(".") or "payload.bin"
        target = folder / f"{digest[:12]}-{clean}"
        target.write_bytes(data)
        record = {"name": target.name, "path": str(target), "kind": category, "size": len(data), "sha256": digest, "status": "extracted", **(metadata or {})}
        self.written += len(data); self.index[digest] = record
        return record


def extract_zip(data: bytes, store: ArtifactStore, limits: Limits, source: str, parent_artifact_id: str | None = None) -> dict:
    """Validate and extract safe ZIP members with central-directory CRC checks.

    Encrypted and unsafe entries are inventoried with an explicit state. Output
    contains entries, artifacts, warnings and safety findings; parser exceptions
    make the container corrupted rather than crashing the full plugin.
    """
    entries, artifacts, warnings = [], [], []
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        return {"status": "corrupted", "entries": [], "artifacts": [], "warnings": [f"ZIP non valido: {exc}"]}
    total = 0
    with archive:
        for info in archive.infolist()[:limits.max_nested_files]:
            pure = PurePosixPath(info.filename.replace("\\", "/"))
            mode = (info.external_attr >> 16) & 0xFFFF
            ratio = info.file_size / max(1, info.compress_size)
            reason = None
            if pure.is_absolute() or ".." in pure.parts or "\x00" in info.filename or (len(info.filename) > 1 and info.filename[1] == ":"): reason = "path traversal"
            elif stat.S_ISLNK(mode): reason = "symlink"
            elif info.flag_bits & 1: reason = "encrypted"
            elif info.file_size > limits.max_single_artifact_size: reason = "single artifact limit"
            elif ratio > limits.max_archive_expansion_ratio: reason = "archive expansion ratio"
            elif total + info.file_size > limits.output_budget: reason = "total output limit"
            entry = {"name": info.filename, "compressed_size": info.compress_size, "size": info.file_size, "crc32": f"{info.CRC:08x}", "ratio": round(ratio, 2), "status": "encrypted" if reason == "encrypted" else "not_applicable" if info.is_dir() else "detected", "rejection_reason": reason}
            entries.append(entry)
            if reason or info.is_dir():
                if reason: warnings.append(f"ZIP {info.filename}: {reason}")
                continue
            try:
                raw = archive.read(info)
                total += len(raw)
                artifact = store.save("container", pure.name, raw, {"source_file": source, "internal_path": info.filename, "technique": "zip_central_directory", "extraction_method": "zip_entry", "parent_artifact_id": parent_artifact_id, "confidence": .99})
                artifacts.append(artifact); entry["status"] = "extracted"
            except (RuntimeError, zipfile.BadZipFile, OSError, ValueError) as exc:
                entry["status"] = "corrupted"; warnings.append(f"ZIP {info.filename}: {exc}")
    if len(archive.infolist()) > limits.max_nested_files:
        warnings.append("max_nested_files raggiunto")
    return {"status": "partial" if warnings else "completed", "entries": entries, "artifacts": artifacts, "warnings": warnings, "extracted_bytes": total}
