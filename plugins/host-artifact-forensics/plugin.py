"""Offline inventory of SQLite-backed host and browser evidence."""
from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import time
from bisect import bisect_right
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

from app.core.flag_detector import search as search_flags
from app.core.plugin import BasePlugin

SQLITE_HEADER = b"SQLite format 3\x00"
BROWSER_NAMES = {"history", "places.sqlite", "cookies", "web data", "login data", "history.db"}
MAX_EVENTS = 10_000
MAX_DATABASES = 128
MAX_COLUMNS = 128
MAX_TEXT = 2048
MAX_FLAG_SCAN_BYTES = 64 * 1024 * 1024


class Plugin(BasePlugin):
    """Parse bounded browser history and inventory SQLite host databases.

    Inputs are copied into the isolated output directory before SQLite opens them.
    WAL bytes are paired with their database when present. Cookie and credential
    values are never selected or returned.
    """

    def can_handle(self, asset, context):
        path_value = asset.get("path")
        if not path_value:
            return {"compatible": False, "score": 0, "reasons": ["È richiesto un database o profilo montato"]}
        path = Path(path_value)
        if path.is_symlink():
            return {"compatible": False, "score": 0, "reasons": ["Symlink non analizzato"]}
        try:
            if path.is_file():
                with path.open("rb") as source:
                    header = source.read(16)
                if header == SQLITE_HEADER:
                    return {"compatible": True, "score": .98, "reasons": ["Header SQLite verificato"]}
                return {"compatible": False, "score": 0, "reasons": ["Header SQLite non presente"]}
            if path.is_dir():
                hints = []
                checked = 0
                walked = 0
                for root, dirs, files in os.walk(path, followlinks=False):
                    walked += 1
                    if walked > 512:
                        return {"compatible": False, "score": 0, "reasons": ["Limite directory profilo raggiunto prima del match SQLite"]}
                    dirs[:] = sorted(d for d in dirs if not (Path(root) / d).is_symlink())
                    for name in sorted(files):
                        checked += 1
                        if checked > 512:
                            if hints:
                                return {"compatible": True, "score": .72, "reasons": hints[:3] + ["Triage directory limitato a 512 file"]}
                            return {"compatible": False, "score": 0, "reasons": ["Nessun database SQLite nei primi 512 file del profilo"]}
                        candidate = Path(root) / name
                        if candidate.is_symlink() or not candidate.is_file():
                            continue
                        if name.casefold() in BROWSER_NAMES:
                            hints.append(f"Nome di database browser: {name}")
                        try:
                            with candidate.open("rb") as source:
                                if source.read(16) == SQLITE_HEADER:
                                    return {"compatible": True, "score": .88, "reasons": [f"SQLite in profilo: {candidate.relative_to(path)}"]}
                        except OSError:
                            continue
                return {"compatible": False, "score": 0, "reasons": ["Nessun database SQLite nei limiti di triage"]}
        except OSError as exc:
            return {"compatible": False, "score": 0, "reasons": [f"Input non leggibile: {exc}"]}
        return {"compatible": False, "score": 0, "reasons": ["Asset non regolare"]}

    def validate(self, asset, context):
        path_value = asset.get("path")
        path = Path(path_value) if path_value else None
        valid = bool(path and not path.is_symlink() and (path.is_file() or path.is_dir()))
        return {"valid": valid, "reason": "È richiesto un file SQLite o una directory profilo regolare" if not valid else ""}

    def analyze(self, asset, context, reporter):
        started = time.monotonic()
        source = Path(asset["path"])
        output = Path(context["output_dir"]) / "host-artifact-forensics"
        work = output / "sqlite-work"
        work.mkdir(parents=True, exist_ok=True)
        byte_budget = max(0, int(context.get("byte_budget", 256 * 1024 * 1024)))
        options = context.get("plugin_options", {}).get("host-artifact-forensics", {})
        event_limit = min(MAX_EVENTS, max(1, int(options.get("max_events", MAX_EVENTS))))
        database_limit = min(MAX_DATABASES, max(1, int(options.get("max_databases", MAX_DATABASES))))
        warnings, inventory, events, flags = [], [], [], []
        copied_bytes = 0
        input_partial = bool(asset.get("partial_input"))
        flag_limit = max(0, min(int(context.get("max_flags", 100)), 100))

        reporter.phase("Ricerca database SQLite")
        candidates, discovery_limited = _discover(source, database_limit)
        if discovery_limited:
            warnings.append(f"Inventario limitato ai primi {database_limit} database SQLite")
        if not candidates:
            warnings.append("Nessun database SQLite valido individuato nella vista disponibile")

        reporter.phase("Inventario e parsing browser")
        deadline = started + float(context.get("plugin_timeout", 300))
        for index, (db_path, relative_name) in enumerate(candidates):
            remaining = byte_budget - copied_bytes
            if remaining <= 0:
                warnings.append("Byte budget globale esaurito durante la copia delle evidenze")
                break
            db_size = db_path.stat().st_size
            target = work / f"{index:04d}-{hashlib.sha256(relative_name.encode()).hexdigest()[:12]}-{_safe_name(db_path.name)}"
            db_hash, db_copied = _copy_bounded(db_path, target, remaining)
            copied_bytes += db_copied
            db_complete = db_copied == db_size
            record = {
                "source_file": relative_name,
                "sha256": db_hash,
                "source_size": db_size,
                "copied_bytes": db_copied,
                "complete_copy": db_complete,
                "wal_present": False,
                "wal_sha256": None,
                "browser": "unknown",
                "tables": [],
            }
            if not db_complete:
                input_partial = True
                warnings.append(f"Database {relative_name} oltre il budget: copiati {db_copied} di {db_size} byte")
                inventory.append(record)
                continue

            wal = Path(str(db_path) + "-wal")
            if wal.is_file() and not wal.is_symlink():
                record["wal_present"] = True
                remaining = byte_budget - copied_bytes
                if remaining:
                    wal_target = Path(str(target) + "-wal")
                    wal_hash, wal_copied = _copy_bounded(wal, wal_target, remaining)
                    copied_bytes += wal_copied
                    record["wal_sha256"] = wal_hash
                    record["wal_bytes"] = wal_copied
                    if wal_copied != wal.stat().st_size:
                        input_partial = True
                        record["complete_wal"] = False
                        warnings.append(f"WAL {relative_name}-wal oltre il budget; snapshot potrebbe essere incompleto")
                    else:
                        record["complete_wal"] = True
                else:
                    input_partial = True
                    warnings.append(f"WAL {relative_name}-wal non copiato: byte budget esaurito")
                    record["complete_wal"] = False

            try:
                browser, tables, rows, db_warnings = _inspect_database(
                    target, relative_name, db_hash, record.get("wal_sha256"), event_limit - len(events), deadline
                )
                record["browser"] = browser
                record["tables"] = tables
                events.extend(rows)
                warnings.extend(db_warnings)
                if browser == "unknown":
                    warnings.append(f"Schema non riconosciuto in {relative_name}; eseguito solo l'inventario SQLite")
                elif record.get("complete_wal") is False:
                    warnings.append(f"Eventi di {relative_name} letti senza WAL completo")
            except (sqlite3.Error, OSError, ValueError) as exc:
                warnings.append(f"Database {relative_name} non interrogabile: {str(exc)[:300]}")
            inventory.append(record)
            if len(events) >= event_limit:
                warnings.append(f"Limite globale di {event_limit} eventi browser raggiunto")
                break
            if time.monotonic() >= deadline:
                warnings.append("Tempo massimo di parsing raggiunto")
                break

        events.sort(key=lambda row: (row.get("timestamp") is None, row.get("timestamp") or "", row["event_id"]))
        if flag_limit:
            flag_text = bytearray()
            flag_spans = []
            for row in events[:min(5000, event_limit)]:
                value = "\n".join(str(row.get(key) or "") for key in ("url", "title"))
                encoded = value.encode("utf-8")
                if not encoded.strip():
                    continue
                if len(flag_text) + len(encoded) > MAX_FLAG_SCAN_BYTES:
                    warnings.append("Ricerca flag fermata al budget cumulativo di 64 MiB")
                    break
                start = len(flag_text)
                flag_text.extend(encoded)
                flag_spans.append((start, len(flag_text), row))
                flag_text.extend(b"\n")
            if flag_text:
                flag_result = search_flags(
                    {"id": asset.get("id", ""), "name": asset.get("name", source.name), "content": flag_text.decode("utf-8", "replace")},
                    {"prefixes": context.get("prefixes", ["flag", "CTF", "HTB", "picoCTF"]),
                     "patterns": context.get("patterns", []), "byte_budget": len(flag_text), "max_results": flag_limit},
                )
                starts = [span[0] for span in flag_spans]
                for flag in flag_result["flags"]:
                    offset = flag.get("offset")
                    if offset is None:
                        offset = flag.get("source_block_offset", 0)
                    index = max(0, bisect_right(starts, offset) - 1)
                    row = flag_spans[index][2]
                    flags.append({**flag, "source_file": row["source_file"], "event_id": row["event_id"], "technique": "browser_history"})
                warnings.extend(flag_result.get("warnings", []))

        domains, domain_sources = {}, {}
        for row in events:
            domain = row.get("domain")
            if domain:
                domains[domain] = domains.get(domain, 0) + 1
                domain_sources.setdefault(domain, set()).add(row["source_file"])
        entities = [{"type": "domain", "value": domain, "event_count": count,
                     "source_files": sorted(domain_sources.get(domain, set()))[:16]}
                    for domain, count in sorted(domains.items(), key=lambda item: (-item[1], item[0]))[:5000]]
        timeline = [{"id": row["event_id"], "timestamp": row.get("timestamp"), "label": row.get("title") or row.get("domain") or row.get("event_type"),
                    "category": row.get("event_type"), "source_file": row["source_file"], "source_sha256": row.get("source_sha256"),
                    "source_snapshot_sha256": row.get("source_snapshot_sha256"), "table": row.get("table"), "row_id": row.get("row_id"),
                    "timestamp_raw": row.get("timestamp_raw"), "timestamp_encoding": row.get("timestamp_encoding"),
                    "domain": row.get("domain"), "severity": "info"}
                   for row in events]
        graph = _domain_graph(inventory, events)
        timeline_visual = {"type": "timeline", "title": "Browser activity", "data": timeline[:2000], "palette": "network", "options": {"interactive": True, "zoom": True, "tooltip": True}}
        graph_visual = {"type": "graph", "title": "Database e domini", "data": graph, "palette": "network", "options": {"interactive": True, "zoom": True, "pan": True, "tooltip": True}}
        status = "partial" if warnings or input_partial else "completed"
        if asset.get("partial_input"):
            warnings.append(f"Input limitato dal core a {asset.get('visible_bytes', 'una vista parziale')} byte")
        sections = [
            _section("database_inventory", "Database SQLite", 10, inventory),
            _section("browser_events", "Cronologia browser", 20, events),
            _section("domain_entities", "Domini osservati", 30, entities),
            _section("cookie_credential_inventory", "Cookie e credenziali: sola presenza", 40,
                     [{"source_file": row["source_file"], "browser": row["browser"], "sensitive_tables": [table["name"] for table in row["tables"] if table["name"].casefold() in {"cookies", "moz_cookies", "logins", "moz_logins", "login_data"}], "values_extracted": False} for row in inventory]),
            _section("timeline", "Timeline", 50, timeline, "timeline"),
            _section("flags", "Flag candidate", 60, flags),
            _section("warnings", "Copertura e diagnostica", 90, warnings, "list"),
        ]
        metrics = {"databases": len(inventory), "browser_events": len(events), "domains": len(entities), "candidate_flags": len(flags),
                   "bytes_copied": copied_bytes, "byte_budget": byte_budget, "partial_input": input_partial,
                   "duration_seconds": round(time.monotonic() - started, 4), "original_modified": False,
                   "sensitive_values_returned": False}
        sections.append(_section("metrics", "Metriche", 100, [metrics], "metrics"))
        result = {"plugin_id": "host-artifact-forensics", "status": status,
                  "summary": f"{len(inventory)} database, {len(events)} eventi browser, {len(entities)} domini",
                  "confidence": .95 if events else .75 if inventory else .25, "phase": "host artifact forensics",
                  "findings": [], "sections": sections, "artifacts": [], "derived_assets": [],
                  "visualizations": [timeline_visual, graph_visual], "flags": flags, "timeline": timeline,
                  "execution_events": [{"phase": "Ricerca e copia database", "status": "partial" if warnings else "completed"},
                                       {"phase": "Parsing SQLite e browser", "status": "partial" if warnings else "completed"}],
                  "logs": [], "warnings": warnings, "errors": [], "metrics": metrics}
        shutil.rmtree(work, ignore_errors=True)
        try:
            output.rmdir()
        except OSError:
            pass
        reporter.partial(result)
        return result

    def create_visualizations(self, result, context):
        return result.get("visualizations", [])

    def search_flags(self, result, context):
        return result.get("flags", [])


def _discover(source: Path, maximum: int):
    if source.is_file():
        with source.open("rb") as stream:
            return ([(source, source.name)] if stream.read(16) == SQLITE_HEADER else []), False
    candidates, scanned, walked, limited = [], 0, 0, False
    for root, dirs, files in os.walk(source, followlinks=False):
        walked += 1
        if walked > 10_000:
            limited = True
            break
        dirs[:] = sorted(name for name in dirs if not (Path(root) / name).is_symlink())
        for name in sorted(files):
            path = Path(root) / name
            if path.is_symlink() or not path.is_file() or name.endswith(("-wal", "-shm")):
                continue
            scanned += 1
            if scanned > 10_000:
                limited = True
                break
            try:
                with path.open("rb") as stream:
                    if stream.read(16) == SQLITE_HEADER:
                        candidates.append((path, str(path.relative_to(source))))
                        if len(candidates) >= maximum:
                            limited = True
                            break
            except OSError:
                continue
        if limited:
            break
    return candidates, limited


def _copy_bounded(source: Path, target: Path, limit: int):
    digest, copied = hashlib.sha256(), 0
    with source.open("rb") as reader, target.open("wb") as writer:
        while copied < limit:
            block = reader.read(min(1024 * 1024, limit - copied))
            if not block:
                break
            writer.write(block); digest.update(block); copied += len(block)
    return digest.hexdigest(), copied


def _inspect_database(path: Path, source_name: str, source_hash: str, wal_hash: str | None, maximum_events: int, deadline: float):
    uri = "file:" + quote(str(path.resolve()), safe="/") + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=2.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA trusted_schema=OFF")
    connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 10_000)
    warnings, events, details = [], [], []
    browser = "unknown"
    snapshot_hash = hashlib.sha256((source_hash + (wal_hash or "checkpointed")).encode()).hexdigest()
    try:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 512")}
        for name in sorted(tables)[:MAX_COLUMNS]:
            columns = [row[1] for row in connection.execute(f'PRAGMA table_info("{name.replace(chr(34), chr(34)*2)}")')][:MAX_COLUMNS]
            details.append({"name": name[:256], "columns": columns})
        if {"urls", "visits"} <= tables:
            browser = "Chromium"
            events.extend(_chromium_events(connection, source_name, source_hash, snapshot_hash, maximum_events))
            if "downloads" in tables and len(events) < maximum_events:
                events.extend(_chromium_downloads(connection, source_name, source_hash, snapshot_hash, maximum_events - len(events)))
        elif {"moz_places", "moz_historyvisits"} <= tables:
            browser = "Firefox"
            events.extend(_firefox_events(connection, source_name, source_hash, snapshot_hash, maximum_events))
        elif {"history_items", "history_visits"} <= tables:
            browser = "Safari"
            events.extend(_safari_events(connection, source_name, source_hash, snapshot_hash, maximum_events))
        elif tables & {"cookies", "moz_cookies", "logins", "moz_logins", "login_data"}:
            browser = "browser profile (schema non classificato)"
        return browser, details, events, warnings
    except sqlite3.DatabaseError as exc:
        warnings.append(f"Errore SQLite su {source_name}: {str(exc)[:240]}")
        return browser, details, events, warnings
    finally:
        connection.close()


def _chromium_events(connection, source, digest, snapshot_digest, limit):
    query = "SELECT v.id AS row_id,u.url,u.title,v.visit_time FROM visits v JOIN urls u ON u.id=v.url ORDER BY v.visit_time DESC LIMIT ?"
    return [_event(source, digest, snapshot_digest, "visits", row["row_id"], "browser_visit", "Chromium", _chrome_time(row["visit_time"]), row["visit_time"], row["url"], row["title"])
            for row in connection.execute(query, (limit,))]


def _chromium_downloads(connection, source, digest, snapshot_digest, limit):
    columns = {row[1] for row in connection.execute('PRAGMA table_info("downloads")')}
    allowed = [name for name in ("id", "target_path", "tab_url", "start_time", "total_bytes", "received_bytes") if name in columns]
    if not allowed:
        return []
    order_by = ' ORDER BY "start_time" DESC' if "start_time" in columns else ' ORDER BY "id" DESC' if "id" in columns else ""
    query = "SELECT " + ",".join('"' + name + '"' for name in allowed) + " FROM downloads" + order_by + " LIMIT ?"
    rows = []
    for index, row in enumerate(connection.execute(query, (limit,))):
        values = dict(row)
        raw_time = values.get("start_time")
        event = _event(source, digest, snapshot_digest, "downloads", values.get("id", index), "browser_download", "Chromium",
                       _chrome_time(raw_time), raw_time, values.get("tab_url"), "")
        event["target_path"] = _bounded_text(values.get("target_path"), MAX_TEXT)
        event["total_bytes"] = values.get("total_bytes")
        event["received_bytes"] = values.get("received_bytes")
        rows.append(event)
    return rows


def _firefox_events(connection, source, digest, snapshot_digest, limit):
    query = "SELECT h.id AS row_id,p.url,p.title,h.visit_date FROM moz_historyvisits h JOIN moz_places p ON p.id=h.place_id ORDER BY h.visit_date DESC LIMIT ?"
    return [_event(source, digest, snapshot_digest, "moz_historyvisits", row["row_id"], "browser_visit", "Firefox", _unix_us(row["visit_date"]), row["visit_date"], row["url"], row["title"])
            for row in connection.execute(query, (limit,))]


def _safari_events(connection, source, digest, snapshot_digest, limit):
    query = "SELECT v.id AS row_id,i.url,i.title,v.visit_time FROM history_visits v JOIN history_items i ON i.id=v.history_item ORDER BY v.visit_time DESC LIMIT ?"
    return [_event(source, digest, snapshot_digest, "history_visits", row["row_id"], "browser_visit", "Safari", _apple_time(row["visit_time"]), row["visit_time"], row["url"], row["title"])
            for row in connection.execute(query, (limit,))]


def _event(source, digest, snapshot_digest, table, row_id, kind, browser, timestamp, raw_time, url, title):
    url = _bounded_text(url, MAX_TEXT)
    title = _bounded_text(title, MAX_TEXT)
    domain = ""
    if url:
        from urllib.parse import urlsplit
        try:
            domain = (urlsplit(url).hostname or "").casefold()[:253]
        except ValueError:
            domain = ""
    event_id = f"{snapshot_digest[:16]}:{table}:{row_id}"
    return {"event_id": event_id, "source_file": source, "source_sha256": digest,
            "source_snapshot_sha256": snapshot_digest, "table": table,
            "row_id": row_id, "timestamp": timestamp, "timestamp_raw": raw_time, "event_type": kind,
            "timestamp_encoding": {"Chromium": "microseconds since 1601-01-01 UTC", "Firefox": "microseconds since Unix epoch", "Safari": "seconds since 2001-01-01 UTC"}.get(browser),
            "application": browser, "url": url, "title": title, "domain": domain, "confidence": .98}


def _chrome_time(value):
    try:
        return (datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=int(value))).isoformat()
    except (ValueError, TypeError, OverflowError):
        return None


def _unix_us(value):
    try:
        return datetime.fromtimestamp(int(value) / 1_000_000, UTC).isoformat()
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def _apple_time(value):
    try:
        return (datetime(2001, 1, 1, tzinfo=UTC) + timedelta(seconds=float(value))).isoformat()
    except (ValueError, TypeError, OverflowError):
        return None


def _bounded_text(value, limit):
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    text = str(value)
    return text[:limit]


def _safe_name(value):
    name = "".join(char for char in value if char.isalnum() or char in "._-")[:100]
    return name or "database.sqlite"


def _section(section_id, title, order, content, kind="table"):
    return {"id": section_id, "section_id": section_id, "title": title, "order": order,
            "status": "completed", "content": content, "data": content, "type": kind,
            "result_count": len(content) if isinstance(content, list) else 1}


def _domain_graph(inventory, events):
    nodes, edges, node_ids, edge_ids = [], [], set(), set()
    domains_by_source = {}
    for event in events:
        if event.get("domain"):
            domains_by_source.setdefault(event["source_file"], set()).add(event["domain"])
    for index, record in enumerate(inventory):
        node_id = f"db-{index}"
        nodes.append({"id": node_id, "type": "asset", "label": record["source_file"], "status": "partial" if not record.get("complete_copy") or record.get("complete_wal") is False else "completed"})
        node_ids.add(node_id)
        for domain in sorted(domains_by_source.get(record["source_file"], set())):
            domain_id = "domain-" + hashlib.sha256(domain.encode()).hexdigest()[:12]
            if domain_id not in node_ids and len(nodes) < 5000:
                nodes.append({"id": domain_id, "type": "entity", "label": domain, "status": "completed"})
                node_ids.add(domain_id)
            edge_id = (node_id, domain_id)
            if edge_id not in edge_ids and len(edges) < 10000 and domain_id in node_ids:
                edges.append({"source": node_id, "target": domain_id, "type": "observed_in", "label": "browser history"})
                edge_ids.add(edge_id)
    return {"nodes": nodes, "edges": edges}
