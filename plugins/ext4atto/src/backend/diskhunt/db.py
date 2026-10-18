from __future__ import annotations
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS jobs (
 id TEXT PRIMARY KEY, status TEXT NOT NULL, phase TEXT NOT NULL, progress REAL NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, input_name TEXT NOT NULL, image_path TEXT NOT NULL,
 original_path TEXT, case_name TEXT NOT NULL DEFAULT '',
 options TEXT NOT NULL, stats TEXT NOT NULL DEFAULT '{}', warnings TEXT NOT NULL DEFAULT '[]',
 error TEXT, cancel_requested INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS results (
 id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL,
 FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_results_job_kind ON results(job_id, kind);
CREATE TABLE IF NOT EXISTS logs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL, created_at TEXT NOT NULL,
 level TEXT NOT NULL, message TEXT NOT NULL, command TEXT, raw_output TEXT
);
"""


class Database:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as con:
            con.executescript(SCHEMA)
            columns = {row[1] for row in con.execute("PRAGMA table_info(jobs)")}
            if "original_path" not in columns: con.execute("ALTER TABLE jobs ADD COLUMN original_path TEXT")
            if "case_name" not in columns: con.execute("ALTER TABLE jobs ADD COLUMN case_name TEXT NOT NULL DEFAULT ''")
            con.execute("UPDATE jobs SET original_path=image_path WHERE original_path IS NULL")

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(self.path, timeout=30)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        finally:
            con.close()

    def create_job(self, job_id: str, input_name: str, image_path: str, options: dict[str, Any], case_name: str = "") -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as con:
            con.execute("INSERT INTO jobs(id,status,phase,progress,created_at,updated_at,input_name,image_path,original_path,case_name,options) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (job_id, "QUEUED", "upload complete", 0, now, now, input_name, image_path, image_path, case_name or input_name, json.dumps(options)))

    def update_job(self, job_id: str, **values: Any) -> None:
        allowed = {"status", "phase", "progress", "stats", "warnings", "error", "cancel_requested", "image_path"}
        values = {k: (json.dumps(v) if k in {"stats", "warnings"} else v) for k, v in values.items() if k in allowed}
        values["updated_at"] = datetime.now(timezone.utc).isoformat()
        sql = ",".join(f"{key}=?" for key in values)
        with self.connect() as con:
            con.execute(f"UPDATE jobs SET {sql} WHERE id=?", (*values.values(), job_id))

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self.connect() as con:
            row = con.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            return None
        data = dict(row)
        for key in ("options", "stats", "warnings"):
            data[key] = json.loads(data[key])
        return data

    def add_result(self, job_id: str, kind: str, data: dict[str, Any]) -> None:
        with self.connect() as con:
            con.execute("INSERT INTO results(job_id,kind,data) VALUES(?,?,?)", (job_id, kind, json.dumps(data)))

    def results(self, job_id: str, kind: str, limit: int = 5000, offset: int = 0) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute("SELECT data FROM results WHERE job_id=? AND kind=? ORDER BY id LIMIT ? OFFSET ?", (job_id, kind, limit, offset)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def clear_results(self, job_id: str) -> None:
        with self.connect() as con:
            con.execute("DELETE FROM results WHERE job_id=?", (job_id,))

    def delete_job(self, job_id: str) -> None:
        with self.connect() as con:
            con.execute("DELETE FROM logs WHERE job_id=?", (job_id,))
            con.execute("DELETE FROM results WHERE job_id=?", (job_id,))
            con.execute("DELETE FROM jobs WHERE id=?", (job_id,))

    def expired_terminal_jobs(self, cutoff: str) -> list[str]:
        with self.connect() as con:
            rows = con.execute("SELECT id FROM jobs WHERE updated_at < ? AND status IN ('COMPLETED','PARTIAL','FAILED','CANCELLED')", (cutoff,)).fetchall()
        return [row[0] for row in rows]

    def list_jobs(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute("SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        jobs = []
        for row in rows:
            item = dict(row)
            for key in ("options", "stats", "warnings"): item[key] = json.loads(item[key])
            jobs.append(item)
        return jobs

    def log(self, job_id: str, level: str, message: str, command: str | None = None, raw_output: str | None = None) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as con:
            con.execute("INSERT INTO logs(job_id,created_at,level,message,command,raw_output) VALUES(?,?,?,?,?,?)",
                        (job_id, now, level, message, command, raw_output))

    def logs(self, job_id: str) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute("SELECT created_at,level,message,command,raw_output FROM logs WHERE job_id=? ORDER BY id", (job_id,)).fetchall()
        return [dict(row) for row in rows]
