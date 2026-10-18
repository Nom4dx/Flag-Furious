from __future__ import annotations

import json
import re
import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..scanner import ScanConfig, scan_bytes
from ..util import iter_files, mime_for, sha256_file

CACHE_PARTS = {"cache", "cache_data", "code cache", "gpucache", "indexeddb", "local storage", "session storage", "service worker"}
SENSITIVE_COLUMNS = re.compile(r"(?i)(token|cookie|session|pass(word)?|secret|auth|encrypted_value|login)")


def _redact_row(item: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    redacted: dict[str, Any] = {}
    changed = False
    import hashlib
    for key, value in item.items():
        if value is not None and SENSITIVE_COLUMNS.search(key):
            raw = value if isinstance(value, bytes) else str(value).encode("utf-8", "replace")
            redacted[key] = f"<REDACTED len={len(raw)} sha256={hashlib.sha256(raw).hexdigest()}>"
            changed = True
        else:
            redacted[key] = value
    return redacted, changed


def application(path: Path) -> str:
    lower = str(path).lower()
    for marker, app in (("chrome", "Chrome"), ("chromium", "Chromium"), ("edge", "Edge"), ("firefox", "Firefox"), ("safari", "Safari"), ("slack", "Slack"), ("discord", "Discord")):
        if marker in lower:
            return app
    if "electron" in lower:
        return "Electron"
    return "Unknown"


def _sqlite_copy(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    target = output / (source.name + "_" + sha256_file(source)[:10] + ".sqlite")
    shutil.copy2(source, target)
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(str(source) + suffix)
        if sidecar.is_file():
            shutil.copy2(sidecar, Path(str(target) + suffix))
    return target


def sqlite_inventory(path: Path, output: Path, config: ScanConfig) -> tuple[dict[str, Any], list]:
    copy = _sqlite_copy(path, output)
    result: dict[str, Any] = {"source": str(path), "copy": str(copy), "tables": [], "rows": [], "freelist": None, "wal": Path(str(path) + "-wal").is_file()}
    findings = []
    try:
        conn = sqlite3.connect(f"file:{copy}?mode=ro", uri=True)
        result["freelist"] = conn.execute("PRAGMA freelist_count").fetchone()[0]
        tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'") if not row[0].startswith("sqlite_")]
        result["tables"] = tables
        for table in tables[:100]:
            safe_table = table.replace('"', '""')
            try:
                cursor = conn.execute(f'SELECT * FROM "{safe_table}" LIMIT 10000')
                columns = [item[0] for item in cursor.description or []]
                for row in cursor:
                    item, redacted = _redact_row(dict(zip(columns, row)))
                    serial = json.dumps(item, default=str, ensure_ascii=False)
                    result["rows"].append({"table": table, "data": item, "credentials_redacted": redacted})
                    findings.extend(scan_bytes(serial.encode(), source=str(path), path=f"{path}:{table}", module="cache", config=config, method="sqlite-row"))
            except sqlite3.DatabaseError:
                continue
        conn.close()
    except sqlite3.DatabaseError as exc:
        result["error"] = str(exc)
    # Raw pages, freelist and WAL remain searchable even when the schema is corrupt.
    for raw_path in (path, Path(str(path) + "-wal"), Path(str(path) + "-journal")):
        if raw_path.is_file():
            findings.extend(scan_bytes(raw_path.read_bytes()[:64 * 1024 * 1024], source=str(path), path=str(raw_path), module="cache", config=config, method="sqlite-raw-pages"))
    return result, findings


def analyze(root: Path, output: Path, config: ScanConfig) -> dict[str, Any]:
    entries = []
    databases = []
    findings = []
    for path in iter_files(root):
        lower_parts = {part.lower() for part in path.parts}
        is_cache = bool(lower_parts & CACHE_PARTS) or path.suffix.lower() in {".ldb", ".log", ".sqlite", ".db", ".wal", ".journal"}
        if not is_cache:
            continue
        stat = path.stat()
        entries.append({"application": application(path), "profile": path.parent.name, "path": str(path),
                        "url": None, "created": datetime.fromtimestamp(stat.st_ctime, UTC).isoformat(),
                        "accessed": datetime.fromtimestamp(stat.st_atime, UTC).isoformat(), "size": stat.st_size,
                        "mime": mime_for(path), "sha256": sha256_file(path), "status": "active", "confidence": 0.85})
        raw = path.read_bytes()[:64 * 1024 * 1024]
        findings.extend(scan_bytes(raw, source=str(root), path=str(path), module="cache", config=config))
        if raw.startswith(b"SQLite format 3\x00"):
            db, db_findings = sqlite_inventory(path, output, config)
            databases.append(db); findings.extend(db_findings)
    return {"entries": entries, "databases": databases, "findings": findings}
