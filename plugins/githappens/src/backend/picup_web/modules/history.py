from __future__ import annotations

import json
import re
import shutil
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ..scanner import ScanConfig, scan_bytes
from ..util import iter_files, sha256_file

SHELL_NAMES = {".bash_history": "Bash", ".zsh_history": "Zsh", "fish_history": "Fish", "consolehost_history.txt": "PowerShell"}
BROWSER_NAMES = {"history", "places.sqlite", "formhistory.sqlite", "favicons", "cookies", "web data", "login data"}


def chromium_time(value: Any) -> str | None:
    try:
        return (datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=int(value))).isoformat()
    except (ValueError, TypeError, OverflowError):
        return None


def firefox_time(value: Any) -> str | None:
    try:
        return datetime.fromtimestamp(int(value) / 1_000_000, UTC).isoformat()
    except (ValueError, TypeError, OverflowError):
        return None


def _copy_db(path: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    target = output / f"{sha256_file(path)[:12]}_{path.name}.sqlite"
    shutil.copy2(path, target)
    for suffix in ("-wal", "-shm"):
        source = Path(str(path) + suffix)
        if source.is_file():
            shutil.copy2(source, Path(str(target) + suffix))
    return target


def browser_events(path: Path, output: Path) -> list[dict[str, Any]]:
    copy = _copy_db(path, output)
    events: list[dict[str, Any]] = []
    try:
        conn = sqlite3.connect(f"file:{copy}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if {"urls", "visits"} <= tables:
            query = "SELECT u.url,u.title,v.visit_time,v.from_visit FROM visits v JOIN urls u ON u.id=v.url ORDER BY v.visit_time"
            for row in conn.execute(query):
                events.append({"timestamp": chromium_time(row["visit_time"]), "type": "browser_visit", "application": "Chromium", "user": None, "path": str(path), "url": row["url"], "command": None, "title": row["title"], "origin": str(path), "confidence": 1.0})
        if "moz_places" in tables:
            query = "SELECT p.url,p.title,h.visit_date FROM moz_places p LEFT JOIN moz_historyvisits h ON h.place_id=p.id ORDER BY h.visit_date"
            for row in conn.execute(query):
                events.append({"timestamp": firefox_time(row["visit_date"]), "type": "browser_visit", "application": "Firefox", "user": None, "path": str(path), "url": row["url"], "command": None, "title": row["title"], "origin": str(path), "confidence": 1.0})
        if "downloads" in tables:
            for row in conn.execute("SELECT * FROM downloads LIMIT 100000"):
                item = dict(row)
                events.append({"timestamp": chromium_time(item.get("start_time")), "type": "download", "application": "Chromium", "user": None, "path": item.get("target_path"), "url": item.get("tab_url"), "command": None, "origin": str(path), "confidence": 1.0})
        conn.close()
    except sqlite3.DatabaseError:
        pass
    return events


def shell_events(path: Path) -> list[dict[str, Any]]:
    app = SHELL_NAMES.get(path.name.lower(), "Shell")
    events = []
    for line in path.read_text("utf-8", "replace").splitlines():
        timestamp = None
        command = line
        if app == "Zsh" and line.startswith(": "):
            match = re.match(r": (\d+):\d+;(.*)", line)
            if match:
                timestamp = datetime.fromtimestamp(int(match.group(1)), UTC).isoformat(); command = match.group(2)
        elif app == "Fish" and line.startswith("- cmd: "):
            command = line[7:]
        if command.strip():
            events.append({"timestamp": timestamp, "type": "shell_command", "application": app, "user": path.parent.name,
                           "path": str(path), "url": None, "command": command, "origin": str(path), "confidence": 0.95})
    return events


def analyze(root: Path, output: Path, config: ScanConfig) -> dict[str, Any]:
    events = []
    findings = []
    for path in iter_files(root):
        lower = path.name.lower()
        if lower in SHELL_NAMES:
            rows = shell_events(path); events.extend(rows)
            for row in rows:
                findings.extend(scan_bytes(row["command"].encode(), source=str(path), path=str(path), module="history", config=config, method="shell-history"))
        elif lower in BROWSER_NAMES and path.read_bytes()[:16] == b"SQLite format 3\x00":
            rows = browser_events(path, output); events.extend(rows)
            for row in rows:
                serial = json.dumps(row, ensure_ascii=False).encode()
                findings.extend(scan_bytes(serial, source=str(path), path=str(path), module="history", config=config, method="browser-history"))
    events.sort(key=lambda item: item.get("timestamp") or "")
    return {"events": events, "findings": findings}
