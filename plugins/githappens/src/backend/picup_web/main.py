from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .cases import CaseStore
from .pipeline import Pipeline
from .util import inside

DATA_DIR = Path(os.environ.get("GITHAPPENS_DATA_DIR", Path.cwd() / "data"))
FRONTEND_DIR = Path(os.environ.get("GITHAPPENS_FRONTEND_DIR", Path(__file__).resolve().parents[2] / "frontend"))
MAX_UPLOAD = int(os.environ.get("GITHAPPENS_MAX_UPLOAD_BYTES", str(20 * 1024 * 1024 * 1024)))
ARTIFACT_PREVIEW_LIMIT = 2 * 1024 * 1024
store = CaseStore(DATA_DIR)
pipeline = Pipeline(store)
executor = ThreadPoolExecutor(max_workers=int(os.environ.get("GITHAPPENS_WORKERS", "2")), thread_name_prefix="githappens")
app = FastAPI(title="GitHappens Forensics", version="1.0.0")


@app.get("/api/health")
def health():
    return {"status": "ok", "product": "GitHappens", "version": "1.0.0", "read_only_evidence": True, "standalone": True}


@app.get("/api/cases")
def list_cases():
    return store.list()


@app.post("/api/cases", status_code=202)
def create_case(
    evidence: UploadFile = File(...), reference: UploadFile | None = File(None), name: str = Form(""),
    prefixes: str = Form(""), regex: str = Form(""), case_sensitive: bool = Form(False), timezone: str = Form("Europe/Rome"),
):
    if not evidence.filename:
        raise HTTPException(400, "Missing evidence filename")
    # Spooled uploads are copied once into a private case and immediately made read-only.
    try:
        manifest = store.create(name, evidence.filename, evidence.file, reference.filename if reference else None, reference.file if reference else None, max_bytes=MAX_UPLOAD)
    except ValueError as exc:
        raise HTTPException(413, str(exc))
    manifest["configuration"] = {"prefixes": prefixes, "regex": regex, "case_sensitive": case_sensitive, "timezone": timezone}
    store.save(manifest["id"], manifest)
    executor.submit(pipeline.run, manifest["id"])
    return {"id": manifest["id"], "status": "queued"}


@app.get("/api/cases/{case_id}")
def get_case(case_id: str):
    try:
        return store.load(case_id)
    except KeyError:
        raise HTTPException(404, "Case not found")


@app.get("/api/cases/{case_id}/results")
def filtered_results(case_id: str, module: str | None = None, q: str = "", mime: str | None = None, since: str | None = None, until: str | None = None):
    try:
        manifest = store.load(case_id)
    except KeyError:
        raise HTTPException(404, "Case not found")
    needle = q.casefold()
    def keep(row):
        if module and row.get("module") != module:
            return False
        if mime and not row.get("mime", "").startswith(mime):
            return False
        timestamp = row.get("timestamp") or row.get("timestamp_utc") or ""
        if since and timestamp and timestamp < since:
            return False
        if until and timestamp and timestamp > until:
            return False
        return not needle or needle in json.dumps(row, ensure_ascii=False, default=str).casefold()
    return {"artifacts": [x for x in manifest["artifacts"] if keep(x)],
            "findings": [x for x in manifest["findings"] if keep(x)],
            "timeline": [x for x in manifest["timeline"] if keep(x)]}


@app.get("/api/cases/{case_id}/report")
def report(case_id: str):
    try:
        path = store.path(case_id) / "manifest.json"
    except KeyError:
        raise HTTPException(404, "Case not found")
    return FileResponse(path, media_type="application/json", filename=f"{case_id}-report.json")


@app.post("/api/cases/{case_id}/cancel", status_code=202)
def cancel_case(case_id: str):
    try:
        store.path(case_id)
    except KeyError:
        raise HTTPException(404, "Case not found")
    pipeline.cancel(case_id)
    return {"status": "cancellation_requested"}


@app.post("/api/cases/{case_id}/modules/{module}", status_code=202)
def rerun_module(case_id: str, module: str):
    allowed = {"extract", "virtual", "legacy", "git", "diff", "slack", "cache", "history", "scan"}
    if module not in allowed:
        raise HTTPException(400, "Unknown module")
    try:
        manifest = store.load(case_id)
    except KeyError:
        raise HTTPException(404, "Case not found")
    if manifest["status"] == "running":
        raise HTTPException(409, "Case is already running")
    executor.submit(pipeline.run, case_id, only=module)
    return {"status": "queued", "module": module}


@app.delete("/api/cases/{case_id}")
def delete_case(case_id: str):
    try:
        manifest = store.load(case_id)
    except KeyError:
        return JSONResponse({"status": "already_deleted", "message": "Caso già eliminato."}, status_code=200)
    if manifest["status"] == "running":
        pipeline.cancel(case_id)
        raise HTTPException(409, "Analysis is running; cancellation requested. Retry deletion after it stops.")
    store.delete(case_id)
    return {"status": "deleted", "message": "Caso eliminato correttamente."}


@app.get("/api/cases/{case_id}/artifacts/{artifact_id}")
def artifact(case_id: str, artifact_id: str, preview: bool = False):
    try:
        manifest = store.load(case_id); case_dir = store.path(case_id)
    except KeyError:
        raise HTTPException(404, "Case not found")
    item = next((row for row in manifest["artifacts"] if row["id"] == artifact_id), None)
    if item is None:
        raise HTTPException(404, "Artifact not found")
    path = inside(case_dir, case_dir / item["path"])
    if preview and item["mime"].startswith(("text/", "application/json", "application/xml")):
        with path.open("rb") as source:
            raw = source.read(ARTIFACT_PREVIEW_LIMIT + 1)
        truncated = len(raw) > ARTIFACT_PREVIEW_LIMIT
        text = raw[:ARTIFACT_PREVIEW_LIMIT].decode("utf-8", "replace")
        if truncated:
            text += "\n[Anteprima limitata a 2 MiB]"
        return HTMLResponse("<pre>" + _escape(text) + "</pre>")
    disposition = "inline" if preview and (item["mime"].startswith("image/") or item["mime"] == "application/pdf") else "attachment"
    return FileResponse(path, media_type=item["mime"], filename=path.name, content_disposition_type=disposition)


@app.get("/api/cases/{case_id}/events")
def events(case_id: str):
    def stream():
        import time
        previous = None
        while True:
            try:
                current = store.load(case_id)
            except KeyError:
                yield "event: deleted\ndata: {}\n\n"; return
            payload = json.dumps({key: current.get(key) for key in ("status", "phase", "progress", "result")})
            if payload != previous:
                yield f"data: {payload}\n\n"; previous = payload
            if current["status"] in {"complete", "failed", "cancelled"}:
                return
            time.sleep(1)
    return StreamingResponse(stream(), media_type="text/event-stream")


def _escape(value: str) -> str:
    import html
    return html.escape(value)


@app.get("/", response_class=HTMLResponse)
def index():
    index_file = FRONTEND_DIR / "index.html"
    if index_file.is_file():
        return index_file.read_text("utf-8")
    return "<h1>GitHappens Forensics</h1><p>Frontend not installed.</p>"


if (FRONTEND_DIR / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIR / "assets"), name="assets")


def run() -> None:
    import uvicorn
    uvicorn.run("picup_web.main:app", host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), reload=False)
