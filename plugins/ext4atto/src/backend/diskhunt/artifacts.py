from __future__ import annotations
import hashlib
import mimetypes
import shutil
import subprocess
import struct
from pathlib import Path
from typing import Any
from .db import Database
from .scanner import scan_bytes


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
        try:
            result = subprocess.run([binary, "--brief", "--mime-type", "--", str(path)], capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip(): return result.stdout.strip()
        except subprocess.TimeoutExpired: pass
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

    def register(self, path: Path, **origin: Any) -> dict[str, Any]:
        path = path.resolve()
        if self.root not in path.parents: raise ValueError("artifact is outside case root")
        relative = str(path.relative_to(self.root)); mime = detect_mime(path); size = path.stat().st_size
        record = {
            "name_original": origin.pop("name_original", path.name), "name_generated": path.name,
            "original_path": origin.pop("original_path", ""), "artifact": relative,
            "mime_type": mime, "size": size, "sha256": file_sha256(path),
            "method": origin.pop("method", "filesystem"), "status": origin.pop("status", "VISIBLE"),
            "confidence": origin.pop("confidence", 95), **origin,
        }
        self.db.add_result(self.job_id, "artifact", record)
        scan_method = "carving" if record["status"] == "CARVED" else "inode"
        if size <= 64 * 1024 * 1024:
            data = path.read_bytes()
            for flag in scan_bytes(data, 0, self.patterns, source=relative, method=scan_method):
                flag.update({"absolute_offset": -1, "partition_offset": -1, "file_source": relative,
                             "inode": record.get("inode"), "partition": record.get("partition"),
                             "filesystem": record.get("filesystem", "unknown")})
                self.db.add_result(self.job_id, "flag", flag)
        return record
