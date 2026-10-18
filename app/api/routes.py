"""Central REST surface. Plugins register only beneath their own namespace."""

import json
from pathlib import Path
from fastapi import Request
from fastapi.responses import FileResponse, Response
from starlette.concurrency import run_in_threadpool
from app.models.contracts import JobRequest, CaseInput, AssetInput, FlagSearch
from app.models.workflows import WorkflowInput, WorkflowRunInput
from app.core.report_generator import report, render_html
from app.services.store import now
from app.core.presentation import present, present_graph


def register_routes(app, settings):
    @app.get("/api/health")
    def health():
        return {
            "status": "ok",
            "sandbox": app.state.sandbox.available,
            "sandbox_error": app.state.sandbox.reason,
            "plugins": sum(p["available"] for p in app.state.registry.plugins.values()),
            "connectors": sum(item["available"] for item in app.state.connectors.items.values()),
            "plugin_errors": app.state.registry.errors,
            "magic_wrapper": "integrated: preserved legacy source + bounded adapter",
            "visualizations": sorted(__import__("app.core.visualization_engine", fromlist=["TYPES"]).TYPES),
            "palettes": sorted(__import__("app.core.visualization_engine", fromlist=["PALETTES"]).PALETTES),
        }

    @app.get("/api/plugins")
    def plugins():
        items = [app.state.registry.public(p) for p in app.state.registry.plugins.values()]
        return {
            "plugins": items,
            "errors": app.state.registry.errors,
            "message": "Nessun plugin disponibile. Inserisci un plugin nella cartella /plugins"
            if not any(p["available"] for p in items)
            else "",
        }

    @app.get("/api/connectors")
    def connectors():
        return app.state.connectors.public()

    @app.post("/api/workflows", status_code=201)
    def create_workflow(body: WorkflowInput):
        """Create a case-scoped connector graph without persisting secrets."""
        return app.state.workflows.save(body)

    @app.get("/api/workflows")
    def workflows(case_id: str):
        app.state.store.get("case", case_id)
        return app.state.store.list("workflow", case_id)

    @app.get("/api/workflows/{workflow_id}")
    def workflow(workflow_id: str):
        return app.state.store.get("workflow", workflow_id)

    @app.put("/api/workflows/{workflow_id}")
    def update_workflow(workflow_id: str, body: WorkflowInput):
        current = app.state.store.get("workflow", workflow_id)
        if current["case_id"] != body.case_id:
            raise ValueError("Il workflow non può essere spostato in un altro caso")
        return app.state.workflows.save(body, workflow_id)

    @app.delete("/api/workflows/{workflow_id}")
    def delete_workflow(workflow_id: str):
        app.state.store.get("workflow", workflow_id)
        app.state.store.delete("workflow", workflow_id)
        return {"deleted": workflow_id}

    @app.post("/api/workflows/{workflow_id}/run", status_code=202)
    def run_workflow(workflow_id: str, body: WorkflowRunInput):
        return app.state.workflows.run(workflow_id, body.secrets)

    @app.get("/api/workflow-runs/{run_id}")
    def workflow_run(run_id: str):
        return app.state.store.get("workflow_run", run_id)

    @app.post("/api/workflow-runs/{run_id}/cancel")
    def cancel_workflow_run(run_id: str):
        return app.state.workflows.cancel(run_id)

    @app.get("/api/plugins/{plugin_id}")
    def plugin(plugin_id: str):
        return app.state.registry.public(app.state.registry.plugins[app.state.registry.resolve_id(plugin_id)])

    @app.get("/api/plugins/bruteforce/wordlists")
    def bruteforce_wordlists(search: str = ""):
        """Inventory local wordlists without returning their password contents."""
        from plugins.bruteforce.src.wordlist_discovery import roots
        from plugins.bruteforce.src.wordlist_manager import inventory

        config_path = settings.storage / "wordlist-roots.json"
        remembered = json.loads(config_path.read_text()).get("roots", []) if config_path.is_file() else []
        configured = [*getattr(settings, "wordlist_roots", ()), *remembered]
        found_roots = roots(settings.root, [], configured)
        items = inventory(found_roots)
        needle = search.casefold().strip()
        if needle:
            items = [x for x in items if needle in (x["name"] + " " + x["relative_path"]).casefold()]
        return {"roots": found_roots, "wordlists": items}

    @app.post("/api/plugins/bruteforce/wordlist-roots")
    async def add_bruteforce_wordlist_root(request: Request):
        """Remember one explicit local directory; syml and missing paths are refused."""
        value = str((await request.json()).get("path", "")).strip()
        path = Path(value).expanduser().resolve()
        if not value or not path.is_dir() or path.is_symlink():
            raise ValueError("Directory wordlist non valida")
        config_path = settings.storage / "wordlist-roots.json"
        roots = json.loads(config_path.read_text()).get("roots", []) if config_path.is_file() else []
        if str(path) not in roots:
            roots.append(str(path))
        config_path.write_text(json.dumps({"roots": roots[-32:]}, indent=2))
        return {"path": str(path), "remembered": True}

    @app.post("/api/cases", status_code=201)
    async def new_case(request: Request):
        body = CaseInput.model_validate(await request.json())
        return app.state.cases.create(body.name)

    @app.get("/api/cases")
    def cases():
        return app.state.store.list("case")

    @app.get("/api/cases/{case_id}")
    def case(case_id: str):
        return {
            **app.state.store.get("case", case_id),
            "assets": [app.state.assets.public(x) for x in app.state.store.list("asset", case_id)],
            "jobs": [
                {k: v for k, v in x.items() if k not in ("results", "graph", "logs")}
                for x in app.state.store.list("job", case_id)
            ],
        }

    @app.delete("/api/cases/{case_id}")
    def delete_case(case_id: str):
        app.state.cases.delete(case_id)
        return {"deleted": case_id}

    @app.post("/api/assets", status_code=201)
    async def create_asset(request: Request):
        items = []
        if "multipart/form-data" in request.headers.get("content-type", ""):
            async with request.form(max_files=128, max_fields=16, max_part_size=2 * 1024**2) as form:
                case_id = str(form.get("case_id", ""))
                app.state.store.get("case", case_id)
                uploads = form.getlist("files") + form.getlist("file")
                if not uploads:
                    raise ValueError("Nessun file caricato")
                parent = None
                if form.get("asset_type") == "directory":
                    from pathlib import PurePosixPath

                    for file in uploads:
                        relative = PurePosixPath(file.filename.replace("\\", "/"))
                        if relative.is_absolute() or ".." in relative.parts:
                            raise ValueError("Percorso directory non sicuro")
                    parent = await run_in_threadpool(
                        app.state.assets.ingest,
                        case_id,
                        "directory",
                        kind="directory",
                        content=[f.filename for f in uploads],
                    )
                    items.append(parent)
                for file in uploads:
                    if not hasattr(file, "file"):
                        raise ValueError("Upload non valido")
                    item = await run_in_threadpool(
                        app.state.assets.ingest,
                        case_id,
                        file.filename,
                        stream=file.file,
                        parent=parent,
                        metadata={"relative_path": file.filename},
                        expected_hash=form.get("expected_hash") or None,
                    )
                    items.append(item)
                if parent:
                    import hashlib

                    parent["entries"] = [
                        {
                            "relative_path": a["metadata"]["relative_path"].replace("\\", "/"),
                            "path": a["path"],
                            "sha256": a["hashes"]["sha256"],
                            "size": a["size"],
                        }
                        for a in items
                        if a.get("parent_id") == parent["id"]
                    ]
                    listing = sorted(
                        [{k: v for k, v in e.items() if k != "path"} for e in parent["entries"]],
                        key=lambda e: e["relative_path"],
                    )
                    parent["hashes"] = {
                        "sha256": hashlib.sha256(json.dumps(listing, sort_keys=True).encode()).hexdigest()
                    }
                    parent["metadata"]["hash_scope"] = (
                        "Canonical JSON listing of relative paths, sizes and content SHA-256 hashes"
                    )
                    parent["size"] = sum(e["size"] for e in parent["entries"])
                    app.state.store.put("asset", parent)
        else:
            body = AssetInput.model_validate(await request.json()).model_dump()
            kind = body.get("type", "text")
            if not isinstance(kind, str) or not kind or len(kind) > 80 or kind == "file":
                raise ValueError("Per i file utilizzare multipart/form-data")
            if kind == "json" and isinstance(body.get("content"), str):
                body["content"] = json.loads(body["content"])
            items.append(
                await run_in_threadpool(
                    app.state.assets.ingest,
                    body["case_id"],
                    body.get("name", "input." + ("json" if kind == "json" else "txt")),
                    kind=kind,
                    content=body.get("content"),
                    metadata=body.get("metadata"),
                )
            )
        return {
            "assets": [
                {
                    **app.state.assets.public(a),
                    "compatible_plugins": await run_in_threadpool(app.state.registry.compatible, a),
                }
                for a in items
            ]
        }

    @app.get("/api/assets/{asset_id}")
    def asset(asset_id: str):
        item = app.state.store.get("asset", asset_id)
        return {**app.state.assets.public(item), "compatible_plugins": app.state.registry.compatible(item)}

    @app.post("/api/assets/{asset_id}/repair", status_code=201)
    async def repair(asset_id: str, request: Request):
        body = await request.json()
        if body.get("confirm") is not True:
            raise ValueError("Richiesta esplicita necessaria: confirm=true")
        asset = app.state.store.get("asset", asset_id)
        if asset["type"] != "file":
            raise ValueError("La riparazione è disponibile solo per i file")
        result = await run_in_threadpool(app.state.sandbox.run, "repair", asset)
        artifact, derived = await run_in_threadpool(
            app.state.artifacts.register, result["artifacts"][0], asset, "magic-wrapper"
        )
        with app.state.store.lock:
            case = app.state.store.get("case", asset["case_id"])
            case["audit"].append(
                {
                    "timestamp": now(),
                    "action": "explicit magic repair",
                    "asset_id": asset_id,
                    "artifact_id": artifact["id"],
                    "before_sha256": asset["hashes"]["sha256"],
                    "after_sha256": derived["hashes"]["sha256"],
                    **result["repair"],
                }
            )
            app.state.store.put("case", case)
        return {"artifact": artifact, "asset": app.state.assets.public(derived), "repair": result["repair"]}

    @app.post("/api/jobs", status_code=202)
    def create_job(body: JobRequest):
        return app.state.jobs.create(body)

    @app.get("/api/jobs/{job_id}")
    def job(job_id: str):
        return {
            k: v
            for k, v in app.state.store.get("job", job_id).items()
            if k not in ("results", "logs", "graph")
        }

    @app.post("/api/jobs/{job_id}/cancel")
    def cancel_job(job_id: str):
        return app.state.jobs.cancel(job_id)

    @app.post("/api/jobs/{job_id}/pause")
    def pause_job(job_id: str):
        return app.state.jobs.pause(job_id)

    @app.post("/api/jobs/{job_id}/resume")
    def resume_job(job_id: str):
        return app.state.jobs.resume(job_id)

    @app.get("/api/jobs/{job_id}/logs")
    def logs(job_id: str, offset: int = 0):
        return app.state.store.get("job", job_id)["logs"][max(0, offset) :]

    @app.get("/api/jobs/{job_id}/results")
    def results(job_id: str):
        return [
            present(result, app.state.registry.plugins.get(result["plugin_id"], {}).get("output_schema", {}))
            for result in app.state.store.get("job", job_id)["results"]
        ]

    @app.get("/api/jobs/{job_id}/graph")
    def graph(job_id: str):
        return present_graph(
            app.state.store.get("job", job_id)["graph"],
            {id: p["output_schema"] for id, p in app.state.registry.plugins.items()},
        )

    @app.get("/api/artifacts/{artifact_id}")
    def artifact(artifact_id: str):
        return app.state.store.get("artifact", artifact_id)

    @app.get("/api/artifacts/{artifact_id}/download")
    def download(artifact_id: str):
        item = app.state.store.get("artifact", artifact_id)
        asset = app.state.store.get("asset", item["asset_id"])
        return FileResponse(asset["path"], filename=item["name"], media_type="application/octet-stream")

    @app.get("/api/artifacts/{artifact_id}/preview")
    def preview(artifact_id: str):
        item = app.state.store.get("artifact", artifact_id)
        asset = app.state.store.get("asset", item["asset_id"])
        with Path(asset["path"]).open("rb") as source:
            data = source.read(65536)
        # Active content is never embedded or served as executable HTML/SVG.
        return {
            "name": item["name"],
            "mime": item["mime"],
            "text": data.decode("utf-8", errors="replace"),
            "hex": data[:4096].hex(" "),
            "partial": item["size"] > len(data),
        }

    @app.post("/api/flags/search")
    async def flags(request: Request):
        body = FlagSearch.model_validate(await request.json()).model_dump()
        asset = (
            app.state.store.get("asset", body["asset_id"])
            if body.get("asset_id")
            else {"type": "text", "content": body.get("text", ""), "id": None}
        )
        from app.core.flag_detector import validate_patterns

        validate_patterns(body.get("prefixes", ["flag", "CTF"]), body.get("patterns", []))
        if not app.state.sandbox.available:
            from app.core.flag_detector import search

            return await run_in_threadpool(search, asset, body)
        return await run_in_threadpool(app.state.sandbox.run, "flags", asset, context=body)

    @app.get("/api/reports/{case_id}")
    def case_report(case_id: str, format: str = "json"):
        value = report(app.state.store, case_id)
        if format not in ("json", "html"):
            raise ValueError("Formato report: json o html")
        content = render_html(value) if format == "html" else json.dumps(value, ensure_ascii=False, indent=2)
        target = settings.storage / "reports" / f"{case_id}.{format}"
        target.write_text(content)
        return Response(
            content,
            media_type="text/html" if format == "html" else "application/json",
            headers={"Content-Disposition": f'attachment; filename="forensic-{case_id}.{format}"'},
        )

    @app.get("/")
    def index():
        return FileResponse(settings.root / "frontend" / "index.html")

    @app.get("/cases/{case_id}/analysis/{job_id}")
    def analysis_page(case_id: str, job_id: str):
        """Serve the reloadable SPA analysis route.

        Case and job existence are checked by the frontend API calls. Returning the
        same local shell keeps routing client-side without a second UI architecture.
        """
        return FileResponse(settings.root / "frontend" / "index.html")

    @app.get("/cases/{case_id}/workflows")
    @app.get("/cases/{case_id}/workflows/{workflow_id}")
    def workflow_page(case_id: str, workflow_id: str | None = None):
        """Serve the reloadable connector editor route."""
        return FileResponse(settings.root / "frontend" / "index.html")

    @app.get("/docs", include_in_schema=False)
    def api_docs():
        return FileResponse(settings.root / "frontend" / "docs.html")
