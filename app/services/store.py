import json
import sqlite3
import threading
from datetime import datetime, timezone
from uuid import uuid4


def uid():
    return uuid4().hex


def now():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, settings):
        self.settings = settings
        self.lock = threading.RLock()
        self.path = settings.storage / "hub.sqlite3"
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute(
                "CREATE TABLE IF NOT EXISTS records (kind TEXT, id TEXT PRIMARY KEY, case_id TEXT, data TEXT)"
            )
            db.execute("CREATE INDEX IF NOT EXISTS records_case ON records(case_id,kind)")

    def connect(self):
        return sqlite3.connect(self.path, timeout=30)

    def put(self, kind, value):
        with self.lock, self.connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO records VALUES(?,?,?,?)",
                (
                    kind,
                    value["id"],
                    value.get("case_id", value["id"] if kind == "case" else ""),
                    json.dumps(value),
                ),
            )
        return value

    def get(self, kind, id):
        with self.connect() as db:
            row = db.execute("SELECT data FROM records WHERE kind=? AND id=?", (kind, id)).fetchone()
        if not row:
            raise KeyError(f"{kind} non trovato")
        return json.loads(row[0])

    def list(self, kind, case_id=None):
        with self.connect() as db:
            rows = db.execute(
                "SELECT data FROM records WHERE kind=?" + (" AND case_id=?" if case_id else ""),
                (kind, case_id) if case_id else (kind,),
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def asset_usage(self, case_id):
        """Return case asset count and retained bytes without decoding every row."""
        with self.connect() as db:
            count, total = db.execute(
                "SELECT COUNT(*), COALESCE(SUM(CAST(json_extract(data, '$.size') AS INTEGER)), 0) "
                "FROM records WHERE kind='asset' AND case_id=?",
                (case_id,),
            ).fetchone()
        return count, total

    def delete_case(self, case_id):
        with self.lock, self.connect() as db:
            db.execute("DELETE FROM records WHERE case_id=?", (case_id,))

    def delete(self, kind, id):
        """Delete one typed record without affecting its case."""
        with self.lock, self.connect() as db:
            db.execute("DELETE FROM records WHERE kind=? AND id=?", (kind, id))
