from __future__ import annotations
import asyncio
import json
import os
import shutil
import uuid
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from pathlib import Path
from threading import Event
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from .analyzer import Analyzer
from .config import settings
from .db import Database
from .models import AnalysisOptions
from .reports import bundle, create_artifact_zip, render
from .security import resolve_artifact, safe_filename

settings.data_dir.mkdir(parents=True, exist_ok=True)
db = Database(settings.database)
executor = ThreadPoolExecutor(max_workers=settings.workers, thread_name_prefix="diskhunt")
cancel_events: dict[str, Event] = {}
job_futures = {}
app = FastAPI(title="DiskHunt Web API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://localhost:8080"], allow_methods=["*"], allow_headers=["*"])


async def cleanup_loop():
    while True:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=settings.job_ttl_hours)).isoformat()
        for expired_id in db.expired_terminal_jobs(cutoff):
            shutil.rmtree(settings.data_dir / "jobs" / expired_id, ignore_errors=True)
            db.delete_job(expired_id)
        await asyncio.sleep(3600)


@app.on_event("startup")
async def start_cleanup():
    asyncio.create_task(cleanup_loop())


def require_job(job_id: str) -> dict:
    job = db.get_job(job_id)
    if not job: raise HTTPException(404, "job not found")
    return job


def start_job(job_id: str):
    cancel_events[job_id] = Event()
    job_futures[job_id] = executor.submit(Analyzer(db, job_id, cancel_events[job_id]).run)


@app.get("/api/health")
def health(): return {"status": "ok", "tsk": bool(shutil.which("fls"))}


@app.post("/api/jobs", status_code=202)
async def create_job(image: UploadFile = File(...), segments: list[UploadFile] = File(default=[]), options: str = Form("{}"), case_name: str = Form("")):
    try: parsed = AnalysisOptions.model_validate_json(options)
    except Exception as exc: raise HTTPException(422, f"invalid options: {exc}") from exc
    original = safe_filename(image.filename or "image.raw")
    allowed = {".dd", ".img", ".raw", ".001", ".gz", ".xz", ".zst", ".e01", ".vhd", ".vmdk", ".qcow2"}
    if Path(original).suffix.lower() not in allowed: raise HTTPException(415, "unsupported image extension")
    job_id = uuid.uuid4().hex; workdir = settings.data_dir / "jobs" / job_id; original_dir = workdir / "original"; original_dir.mkdir(parents=True, mode=0o700)
    target = original_dir / original; total = 0
    try:
        with target.open("xb") as output:
            while chunk := await image.read(1024 * 1024):
                total += len(chunk)
                if total > settings.max_upload_bytes: raise HTTPException(413, "upload exceeds configured limit")
                output.write(chunk)
        for segment in segments:
            segment_name = safe_filename(segment.filename or "segment")
            if not Path(segment_name).suffix.removeprefix(".").isdigit(): raise HTTPException(415, "segment names must end in .001, .002, …")
            segment_target = original_dir / segment_name
            with segment_target.open("xb") as output:
                while chunk := await segment.read(1024 * 1024):
                    total += len(chunk)
                    if total > settings.max_upload_bytes: raise HTTPException(413, "upload exceeds configured limit")
                    output.write(chunk)
            segment_target.chmod(0o400)
        target.chmod(0o400)
    except Exception:
        shutil.rmtree(workdir, ignore_errors=True); raise
    db.create_job(job_id, original, str(target), parsed.model_dump(), safe_filename(case_name, original) if case_name else original)
    start_job(job_id)
    return {"id": job_id, "status": "QUEUED"}


@app.get("/api/jobs")
def list_cases(limit: int = Query(100, ge=1, le=500)):
    return {"items": [{k: v for k, v in job.items() if k not in {"image_path", "original_path", "cancel_requested"}} for job in db.list_jobs(limit)]}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    job = require_job(job_id); return {k: v for k, v in job.items() if k not in {"image_path", "original_path", "cancel_requested"}}


@app.get("/api/jobs/{job_id}/events")
async def events(job_id: str):
    require_job(job_id)
    async def stream():
        last = None
        while True:
            job = require_job(job_id); payload = json.dumps({k: v for k, v in job.items() if k not in {"image_path", "original_path", "cancel_requested"}})
            if payload != last: yield f"data: {payload}\n\n"; last = payload
            if job["status"] in {"COMPLETED", "PARTIAL", "FAILED", "CANCELLED"}: break
            await asyncio.sleep(.75)
    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})


@app.post("/api/jobs/{job_id}/cancel", status_code=202)
def cancel(job_id: str):
    require_job(job_id); db.update_job(job_id, cancel_requested=1)
    cancel_events.setdefault(job_id, Event()).set(); return {"status": "cancellation requested"}


@app.delete("/api/jobs/{job_id}")
def delete_case(job_id: str):
    require_job(job_id)
    event = cancel_events.setdefault(job_id, Event()); event.set(); db.update_job(job_id, cancel_requested=1)
    future = job_futures.get(job_id)
    if future and not future.done():
        try: future.result(timeout=10)
        except FutureTimeout: raise HTTPException(409, "analysis is still stopping; retry deletion shortly")
    workdir = settings.data_dir / "jobs" / job_id
    tombstone = settings.data_dir / "jobs" / f".deleting-{job_id}"
    if workdir.exists(): workdir.rename(tombstone)
    try:
        if tombstone.exists(): shutil.rmtree(tombstone, ignore_errors=False)
        db.delete_job(job_id)
    except Exception as exc:
        if tombstone.exists() and not workdir.exists(): tombstone.rename(workdir)
        raise HTTPException(500, f"case deletion failed safely: {exc}") from exc
    cancel_events.pop(job_id, None); job_futures.pop(job_id, None)
    return {"status": "deleted", "message": "Caso eliminato correttamente."}


@app.post("/api/jobs/{job_id}/resume", status_code=202)
def resume(job_id: str, budgets: str | None = Form(None)):
    job = require_job(job_id)
    if job["status"] not in {"PARTIAL", "FAILED", "CANCELLED"}: raise HTTPException(409, "only partial, failed or cancelled jobs can resume")
    options = job["options"]
    if budgets:
        try: options["budgets"] = json.loads(budgets)
        except json.JSONDecodeError as exc: raise HTTPException(422, "invalid budget JSON") from exc
        with db.connect() as con: con.execute("UPDATE jobs SET options=? WHERE id=?", (json.dumps(options), job_id))
    db.clear_results(job_id); db.update_job(job_id, status="QUEUED", phase="resuming", progress=0, cancel_requested=0, error=None)
    start_job(job_id); return {"status": "QUEUED"}


def result_endpoint(job_id: str, kind: str, limit: int, offset: int):
    require_job(job_id); return {"items": db.results(job_id, kind, limit, offset), "limit": limit, "offset": offset}


@app.get("/api/jobs/{job_id}/partitions")
def partitions(job_id: str, limit: int = Query(500, le=5000), offset: int = 0): return result_endpoint(job_id, "partition", limit, offset)
@app.get("/api/jobs/{job_id}/files")
def files(job_id: str, limit: int = Query(500, le=5000), offset: int = 0, q: str | None = None, extension: str | None = None,
          filesystem: str | None = None, partition: int | None = None, deleted: bool | None = None, inode: int | None = None,
          min_size: int | None = Query(None, ge=0), max_size: int | None = Query(None, ge=0), wildcard: str | None = Query(None, max_length=128),
          name_regex: str | None = Query(None, max_length=128), sort: str = Query("path", pattern="^(path|size|inode|mtime)$"), descending: bool = False):
    require_job(job_id); items = db.results(job_id, "file", 50000) + db.results(job_id, "deleted", 50000)
    if q: items = [x for x in items if q.lower() in x.get("original_path", x.get("name", "")).lower()]
    if extension: items = [x for x in items if Path(x.get("name", "")).suffix.lower() == "." + extension.lower().removeprefix(".")]
    if filesystem: items = [x for x in items if x.get("filesystem") == filesystem]
    if partition is not None: items = [x for x in items if x.get("partition") == partition]
    if deleted is not None: items = [x for x in items if x.get("deleted") is deleted]
    if inode is not None: items = [x for x in items if x.get("inode") == inode]
    if min_size is not None: items = [x for x in items if x.get("size", 0) >= min_size]
    if max_size is not None: items = [x for x in items if x.get("size", 0) <= max_size]
    if wildcard:
        import fnmatch
        items = [x for x in items if fnmatch.fnmatch(x.get("original_path", x.get("name", "")), wildcard)]
    if name_regex:
        import re
        try: expression = re.compile(name_regex, re.IGNORECASE)
        except re.error as exc: raise HTTPException(422, f"invalid filename regex: {exc}") from exc
        items = [x for x in items if expression.search(x.get("original_path", x.get("name", "")))]
    sort_keys = {"path": lambda x: x.get("original_path", x.get("name", "")), "size": lambda x: x.get("size", 0), "inode": lambda x: x.get("inode", 0), "mtime": lambda x: x.get("mtime", "")}
    items.sort(key=sort_keys[sort], reverse=descending)
    return {"items": items[offset:offset+limit], "total": len(items), "limit": limit, "offset": offset}
@app.get("/api/jobs/{job_id}/deleted")
def deleted(job_id: str, limit: int = Query(500, le=5000), offset: int = 0): return result_endpoint(job_id, "deleted", limit, offset)
@app.get("/api/jobs/{job_id}/flags")
def flags(job_id: str, limit: int = Query(500, le=5000), offset: int = 0):
    data = result_endpoint(job_id, "flag", limit, offset); data["items"].sort(key=lambda item: -item["confidence"]); return data
@app.get("/api/jobs/{job_id}/filesystems")
def filesystems(job_id: str, limit: int = Query(500, le=5000), offset: int = 0): return result_endpoint(job_id, "filesystem", limit, offset)
@app.get("/api/jobs/{job_id}/carved")
def carved(job_id: str, limit: int = Query(500, le=5000), offset: int = 0): return result_endpoint(job_id, "carved", limit, offset)


@app.get("/api/jobs/{job_id}/logs")
def logs(job_id: str): require_job(job_id); return {"items": db.logs(job_id)}


@app.get("/api/jobs/{job_id}/artifacts")
def artifacts(job_id: str, limit: int = Query(500, le=5000), offset: int = 0, q: str | None = None, mime: str | None = None, status: str | None = None, scan_status: str | None = None):
    require_job(job_id); items = db.results(job_id, "artifact", 50000)
    if q: items = [x for x in items if q.lower() in (x.get("original_path", "") + x.get("name_original", "")).lower()]
    if mime: items = [x for x in items if x.get("mime_type", "").startswith(mime)]
    if status: items = [x for x in items if x.get("status") == status]
    if scan_status: items = [x for x in items if x.get("flag_scan_status") == scan_status]
    return {"items": items[offset:offset+limit], "total": len(items), "limit": limit, "offset": offset}


@app.get("/api/jobs/{job_id}/artifacts/{file_path:path}/preview")
def preview_artifact(job_id: str, file_path: str):
    require_job(job_id)
    try: target = resolve_artifact(settings.data_dir / "jobs" / job_id / "artifacts", file_path)
    except ValueError as exc: raise HTTPException(404, str(exc)) from exc
    from .artifacts import detect_mime
    mime = detect_mime(target); artifact_root = (settings.data_dir / "jobs" / job_id / "artifacts").resolve()
    relative = str(target.relative_to(artifact_root))
    indexed = next((item for item in db.results(job_id, "artifact", 50000) if item.get("artifact") == relative), None)
    info = {"name": target.name, "mime_type": mime, "size": target.stat().st_size,
            "sha256": indexed.get("sha256") if indexed else None,
            "hash_status": "indexed" if indexed and indexed.get("sha256") else "unavailable"}
    if mime.startswith("text/") or mime in {"application/json", "application/xml"}:
        with target.open("rb") as source: data = source.read(2 * 1024 * 1024)
        encoding = "utf-8"
        try: content = data.decode("utf-8")
        except UnicodeDecodeError: encoding = "latin-1"; content = data.decode("latin-1")
        return {**info, "kind": "text", "encoding": encoding, "content": content, "truncated": target.stat().st_size > len(data)}
    if mime.startswith("image/"):
        from .artifacts import image_dimensions
        return {**info, "kind": "image", "dimensions": image_dimensions(target)}
    if mime == "application/pdf": return {**info, "kind": "pdf"}
    import re
    with target.open("rb") as source: data = source.read(2 * 1024 * 1024)
    strings = [match.decode("ascii", "replace") for match in re.findall(rb"[\x20-\x7e]{4,}", data)[:500]]
    return {**info, "kind": "binary", "magic_bytes": data[:32].hex(), "strings": strings, "truncated": target.stat().st_size > len(data)}


@app.get("/api/jobs/{job_id}/artifacts/{file_path:path}/content")
def artifact_content(job_id: str, file_path: str):
    require_job(job_id)
    try: target = resolve_artifact(settings.data_dir / "jobs" / job_id / "artifacts", file_path)
    except ValueError as exc: raise HTTPException(404, str(exc)) from exc
    from .artifacts import detect_mime
    return FileResponse(target, media_type=detect_mime(target), headers={"Content-Security-Policy": "default-src 'none'; sandbox", "X-Content-Type-Options": "nosniff"})


@app.get("/api/jobs/{job_id}/artifacts/{file_path:path}/hex")
def artifact_hex(job_id: str, file_path: str, offset: int = Query(0, ge=0), length: int = Query(512, ge=1, le=65536)):
    require_job(job_id)
    try: target = resolve_artifact(settings.data_dir / "jobs" / job_id / "artifacts", file_path)
    except ValueError as exc: raise HTTPException(404, str(exc)) from exc
    if offset >= target.stat().st_size: raise HTTPException(416, "offset outside artifact")
    with target.open("rb") as source: source.seek(offset); data = source.read(length)
    return {"offset": offset, "length": len(data), "hex": data.hex(), "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in data)}


def make_report(job_id: str):
    job = require_job(job_id)
    sections = {key: db.results(job_id, kind) for key, kind in {"partitions":"partition", "filesystems":"filesystem", "files":"file", "deleted":"deleted", "recovered":"recovered", "carved":"carved", "flags":"flag"}.items()}
    sections["flags"].sort(key=lambda item: -item["confidence"])
    sections["artifacts"] = db.results(job_id, "artifact")
    return bundle(job, sections, db.logs(job_id))


@app.get("/api/jobs/{job_id}/report")
def report(job_id: str, format: str = Query("json", pattern="^(json|csv|markdown|html|zip)$")):
    data = make_report(job_id)
    if format == "zip": return Response(create_artifact_zip(data, settings.data_dir / "jobs" / job_id / "artifacts"), media_type="application/zip", headers={"Content-Disposition": 'attachment; filename="diskhunt-artifacts.zip"'})
    body, media, name = render(data, format)
    return Response(body, media_type=media, headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.get("/api/jobs/{job_id}/artifacts/{file_path:path}")
def artifact(job_id: str, file_path: str):
    require_job(job_id)
    try: target = resolve_artifact(settings.data_dir / "jobs" / job_id / "artifacts", file_path)
    except ValueError as exc: raise HTTPException(404, str(exc)) from exc
    return FileResponse(target, filename=target.name, media_type="application/octet-stream")


@app.get("/api/jobs/{job_id}/hex")
def hex_range(job_id: str, offset: int = Query(0, ge=0), length: int = Query(512, ge=1, le=65536)):
    job = require_job(job_id); path = Path(job["image_path"])
    if offset >= path.stat().st_size: raise HTTPException(416, "offset outside image")
    with path.open("rb") as source: source.seek(offset); data = source.read(length)
    return {"offset": offset, "length": len(data), "sector": offset // 512, "hex": data.hex(), "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in data)}


frontend = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if frontend.exists(): app.mount("/", StaticFiles(directory=frontend, html=True), name="frontend")
