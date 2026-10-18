from __future__ import annotations
import hashlib
import mimetypes
import shutil
import struct
from pathlib import Path
from typing import Any
from .bounded_process import run_bounded
from .db import Database
from .scanner import scan_file

FLAG_SCAN_LIMIT = 64 * 1024 * 1024
FLAG_FINDING_LIMIT = 10_000


MAGIC_MIME = [
    (b"\x89PNG\r\n\x1a\n", "image/png"), (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF8", "image/gif"), (b"BM", "image/bmp"), (b"RIFF", "image/webp"),
    (b"%PDF-", "application/pdf"), (b"PK\x03\x04", "application/zip"),
    (b"\x1f\x8b", "application/gzip"), (b"\xfd7zXZ\x00", "application/x-xz"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
    (b"Rar!\x1a\x07", "application/vnd.rar"), (b"SQLite format 3\x00", "application/vnd.sqlite3"),
    (b"\x7fELF", "application/x-elf"), (b"MZ", "application/vnd.microsoft.portable-executable"),
]


def detect_mime(path: Path) -> str:
    with path.open("rb") as source: head = source.read(512)
    for magic, mime in MAGIC_MIME:
        if head.startswith(magic):
            if mime == "image/webp" and head[8:12] != b"WEBP": continue
            return mime
    binary = shutil.which("file")
    if binary:
        result = run_bounded([binary, "--brief", "--mime-type", "--", str(path)],
                             timeout=10, max_stdout=4096, max_stderr=4096)
        if result["returncode"] == 0 and not result["timed_out"] and not result["truncated"]:
            detected = result["stdout"].decode("utf-8", "replace").strip()
            if detected:
                return detected
    return mimetypes.guess_type(path.name)[0] or "application/octet-stream"


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024): digest.update(block)
    return digest.hexdigest()


def image_dimensions(path: Path) -> dict[str, int] | None:
    with path.open("rb") as source: data = source.read(256 * 1024)
    if data.startswith(b"\x89PNG") and len(data) >= 24:
        width, height = struct.unpack(">II", data[16:24]); return {"width": width, "height": height}
    if data.startswith((b"GIF87a", b"GIF89a")) and len(data) >= 10:
        width, height = struct.unpack("<HH", data[6:10]); return {"width": width, "height": height}
    if data.startswith(b"BM") and len(data) >= 26:
        width, height = struct.unpack("<ii", data[18:26]); return {"width": abs(width), "height": abs(height)}
    if data.startswith(b"\xff\xd8"):
        cursor = 2
        while cursor + 9 < len(data):
            if data[cursor] != 0xFF: cursor += 1; continue
            marker = data[cursor + 1]; length = int.from_bytes(data[cursor + 2:cursor + 4], "big")
            if marker in range(0xC0, 0xC4):
                return {"width": int.from_bytes(data[cursor+7:cursor+9], "big"), "height": int.from_bytes(data[cursor+5:cursor+7], "big")}
            cursor += max(length + 2, 2)
    return None


class ArtifactCatalog:
    def __init__(self, db: Database, job_id: str, artifact_root: Path, patterns):
        self.db = db; self.job_id = job_id; self.root = artifact_root.resolve(); self.patterns = patterns
        self.coverage_warnings = []
        self.coverage_warnings_omitted = 0

    def register(self, path: Path, **origin: Any) -> dict[str, Any]:
        path = path.resolve()
        if self.root not in path.parents: raise ValueError("artifact is outside case root")
        relative = str(path.relative_to(self.root)); mime = detect_mime(path); size = path.stat().st_size
        flags = []
        if size <= FLAG_SCAN_LIMIT:
            scan_method = "carving" if "carv" in str(origin.get("method", "")).lower() or origin.get("status") == "CARVED" else "inode"
            flags, scanned, scan_partial = scan_file(
                path, self.patterns, source=relative, method=scan_method,
                max_bytes=FLAG_SCAN_LIMIT, max_results=FLAG_FINDING_LIMIT)
            scan_status = "partial" if scan_partial else "complete"
        else:
            scanned, scan_status = 0, "skipped_size_limit"
        if scan_status != "complete":
            warning = f"Artifact flag scan {scan_status}: {relative} ({scanned}/{size} bytes, {len(flags)} findings)."
            if len(self.coverage_warnings) < 100:
                self.coverage_warnings.append(warning)
            else:
                self.coverage_warnings_omitted += 1
        record = {
            "name_original": origin.pop("name_original", path.name), "name_generated": path.name,
            "original_path": origin.pop("original_path", ""), "artifact": relative,
            "mime_type": mime, "size": size, "sha256": file_sha256(path),
            "flag_scan_status": scan_status, "flag_scan_bytes": scanned,
            "flag_scan_findings": len(flags),
            "method": origin.pop("method", "filesystem"), "status": origin.pop("status", "VISIBLE"),
            "confidence": origin.pop("confidence", 95), **origin,
        }
        self.db.add_result(self.job_id, "artifact", record)
        for flag in flags:
            artifact_offset = flag.get("absolute_offset")
            flag.update({"absolute_offset": None, "artifact_offset": artifact_offset,
                         "source_offset_scope": "artifact", "partition_offset": -1, "file_source": relative,
                         "inode": record.get("inode"), "partition": record.get("partition"),
                         "filesystem": record.get("filesystem", "unknown")})
            self.db.add_result(self.job_id, "flag", flag)
        return record
