from __future__ import annotations

import os
import shutil
import sqlite3
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import Artifact, Finding
from .util import inside, json_dump, mime_for, safe_name, sha256_file

OUTPUT_DIRS = ("files", "images", "objects", "qcow", "legacy", "git", "slack", "cache", "history", "diff", "timeline", "flag_candidates", "logs")


class CaseStore:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "cases.sqlite3"
        self.lock = threading.RLock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, name TEXT NOT NULL, created TEXT NOT NULL, status TEXT NOT NULL, progress INTEGER NOT NULL DEFAULT 0, phase TEXT NOT NULL DEFAULT 'queued', case_dir TEXT NOT NULL, error TEXT)")

    def create(self, name: str, filename: str, stream, reference_name: str | None = None, reference_stream=None, *, max_bytes: int | None = None) -> dict[str, Any]:
        case_id = uuid.uuid4().hex
        case_dir = inside(self.root, self.root / case_id)
        evidence = case_dir / "evidence"
        evidence.mkdir(parents=True)
        original = evidence / safe_name(filename, "evidence.bin")
        def copy_bounded(source, target_path: Path) -> None:
            total = 0
            with target_path.open("xb") as output_handle:
                while block := source.read(1024 * 1024):
                    total += len(block)
                    if max_bytes is not None and total > max_bytes:
                        raise ValueError("upload exceeds configured byte limit")
                    output_handle.write(block)
        try:
            copy_bounded(stream, original)
        except Exception:
            shutil.rmtree(case_dir, ignore_errors=True)
            raise
        os.chmod(original, 0o400)
        reference = None
        if reference_stream is not None and reference_name:
            reference = evidence / ("reference_" + safe_name(reference_name))
            try:
                copy_bounded(reference_stream, reference)
            except Exception:
                shutil.rmtree(case_dir, ignore_errors=True)
                raise
            os.chmod(reference, 0o400)
        output = case_dir / f"{safe_name(original.stem)}_githappens"
        for folder in OUTPUT_DIRS:
            (output / folder).mkdir(parents=True, exist_ok=True)
        created = datetime.now(UTC).isoformat()
        manifest = {
            "id": case_id, "name": name or original.stem, "created": created,
            "status": "queued", "phase": "queued", "progress": 0,
            "original": str(original.relative_to(case_dir)),
            "reference": str(reference.relative_to(case_dir)) if reference else None,
            "output": str(output.relative_to(case_dir)), "metadata": {}, "artifacts": [],
            "findings": [], "modules": {}, "timeline": [], "logs": [], "warnings": [], "errors": [],
        }
        json_dump(case_dir / "manifest.json", manifest)
        with self._connect() as conn:
            conn.execute("INSERT INTO cases(id,name,created,status,progress,phase,case_dir) VALUES(?,?,?,?,?,?,?)", (case_id, manifest["name"], created, "queued", 0, "queued", str(case_dir)))
        return manifest

    def path(self, case_id: str) -> Path:
        if not case_id.isalnum() or len(case_id) != 32:
            raise KeyError(case_id)
        path = inside(self.root, self.root / case_id)
        if not path.is_dir():
            raise KeyError(case_id)
        return path

    def load(self, case_id: str) -> dict[str, Any]:
        path = self.path(case_id) / "manifest.json"
        import json
        return json.loads(path.read_text(encoding="utf-8"))

    def save(self, case_id: str, manifest: dict[str, Any]) -> None:
        with self.lock:
            json_dump(self.path(case_id) / "manifest.json", manifest)
            with self._connect() as conn:
                conn.execute("UPDATE cases SET status=?,progress=?,phase=?,error=? WHERE id=?", (manifest["status"], manifest["progress"], manifest["phase"], (manifest.get("errors") or [None])[-1], case_id))

    def list(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            return [dict(row) for row in conn.execute("SELECT id,name,created,status,progress,phase,error FROM cases ORDER BY created DESC")]

    def add_artifact(self, manifest: dict[str, Any], case_dir: Path, path: Path, *, source: str, module: str, method: str, confidence: float = 1.0, status: str = "active", offset: int | None = None, timestamp: str | None = None, metadata: dict[str, Any] | None = None) -> Artifact:
        path = inside(case_dir, path)
        item = Artifact(
            id=uuid.uuid4().hex, source=source, path=str(path.relative_to(case_dir)), offset=offset,
            size=path.stat().st_size, sha256=sha256_file(path), timestamp=timestamp,
            extraction_method=method, module=module, confidence=confidence, status=status,
            mime=mime_for(path), metadata=metadata or {},
        )
        manifest["artifacts"].append(item.dict())
        return item

    def add_findings(self, manifest: dict[str, Any], findings: list[Finding]) -> None:
        known = {(x["module"], x["value"], x.get("path"), x.get("offset"), x.get("method")) for x in manifest["findings"]}
        for finding in findings:
            key = (finding.module, finding.value, finding.path, finding.offset, finding.method)
            if key not in known:
                manifest["findings"].append(finding.dict())
                known.add(key)
        manifest["findings"].sort(key=lambda row: row.get("confidence", 0), reverse=True)

    def delete(self, case_id: str) -> None:
        case_dir = self.path(case_id)
        shutil.rmtree(case_dir)
        with self._connect() as conn:
            conn.execute("DELETE FROM cases WHERE id=?", (case_id,))
