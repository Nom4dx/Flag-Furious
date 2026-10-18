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
MAX_DB_COPY = 128 * 1024 * 1024
MAX_EVENTS = 10_000
MAX_TEXT = 16_384


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
    sidecars = [Path(str(path) + suffix) for suffix in ("-wal", "-shm")]
    total = path.stat().st_size + sum(item.stat().st_size for item in sidecars if item.is_file())
    if total > MAX_DB_COPY:
        raise ValueError(f"SQLite database/WAL oltre {MAX_DB_COPY} byte")
    output.mkdir(parents=True, exist_ok=True)
    target = output / f"{sha256_file(path)[:12]}_{path.name}.sqlite"
    shutil.copy2(path, target)
    for suffix, source in zip(("-wal", "-shm"), sidecars):
        if source.is_file():
            shutil.copy2(source, Path(str(target) + suffix))
    return target


def browser_events(path: Path, output: Path, config: ScanConfig) -> list[dict[str, Any]]:
    try:
        copy = _copy_db(path, output)
    except (OSError, ValueError) as exc:
        config.warn(f"{path.name}: database browser non copiato ({exc})")
        return []
    events: list[dict[str, Any]] = []
    conn = None
    try:
        conn = sqlite3.connect(f"file:{copy}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.set_progress_handler(lambda: int(len(events) >= MAX_EVENTS), 10_000)
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        queries = []
        if {"urls", "visits"} <= tables:
            queries.append(("SELECT u.url,u.title,v.visit_time FROM visits v JOIN urls u ON u.id=v.url ORDER BY v.visit_time LIMIT 10000", "Chromium", chromium_time, "browser_visit"))
        if "moz_places" in tables and "moz_historyvisits" in tables:
            queries.append(("SELECT p.url,p.title,h.visit_date FROM moz_places p LEFT JOIN moz_historyvisits h ON h.place_id=p.id ORDER BY h.visit_date LIMIT 10000", "Firefox", firefox_time, "browser_visit"))
        if "downloads" in tables:
            queries.append(("SELECT start_time,target_path,tab_url FROM downloads LIMIT 10000", "Chromium", chromium_time, "download"))
        for query, app, convert_time, kind in queries:
            try:
                for row in conn.execute(query):
                    if len(events) >= MAX_EVENTS:
                        config.warn(f"{path.name}: eventi browser limitati a {MAX_EVENTS}")
                        break
                    item = dict(row)
                    url = str(item.get("url", item.get("tab_url")) or "")[:MAX_TEXT]
                    title = str(item.get("title") or "")[:MAX_TEXT]
                    events.append({"timestamp": convert_time(item.get("visit_time", item.get("visit_date", item.get("start_time")))),
                                   "type": kind, "application": app, "user": None, "path": str(item.get("target_path") or path),
                                   "url": url, "command": None, "title": title, "origin": str(path), "confidence": 1.0})
            except sqlite3.DatabaseError as exc:
                config.warn(f"{path.name}: query history non completata ({exc})")
    except sqlite3.DatabaseError as exc:
        config.warn(f"{path.name}: SQLite non leggibile ({exc})")
    finally:
        if conn is not None:
            conn.close()
    return events


def shell_events(path: Path, config: ScanConfig) -> list[dict[str, Any]]:
    app = SHELL_NAMES.get(path.name.lower(), "Shell")
    raw = config.read_prefix(path, 8 * 1024 * 1024)
    events = []
    for line in raw.decode("utf-8", "replace").splitlines()[:MAX_EVENTS]:
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
                           "path": str(path), "url": None, "command": command[:MAX_TEXT], "origin": str(path), "confidence": 0.95})
    if len(events) >= MAX_EVENTS:
        config.warn(f"{path.name}: eventi shell limitati a {MAX_EVENTS}")
    return events


def analyze(root: Path, output: Path, config: ScanConfig) -> dict[str, Any]:
    events = []
    findings = []
    for path in iter_files(root, limit=10_000, diagnostics=config.diagnostics):
        lower = path.name.lower()
        if lower in SHELL_NAMES:
            rows = shell_events(path, config)
            events.extend(rows)
            for row in rows:
                findings.extend(scan_bytes(row["command"].encode(), source=str(path), path=str(path), module="history", config=config, method="shell-history"))
        elif lower in BROWSER_NAMES:
            try:
                with path.open("rb") as source:
                    is_sqlite = source.read(16) == b"SQLite format 3\x00"
            except OSError as exc:
                config.warn(f"{path.name}: lettura header fallita ({exc})")
                continue
            if is_sqlite:
                rows = browser_events(path, output, config)
                events.extend(rows)
                for row in rows:
                    serial = json.dumps(row, ensure_ascii=False).encode()
                    findings.extend(scan_bytes(serial, source=str(path), path=str(path), module="history", config=config, method="browser-history"))
        if len(events) >= MAX_EVENTS:
            config.warn(f"Inventario eventi limitato a {MAX_EVENTS}")
            events = events[:MAX_EVENTS]
            break
    events.sort(key=lambda item: item.get("timestamp") or "")
    return {"events": events, "findings": findings}
