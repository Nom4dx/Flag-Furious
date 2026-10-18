import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.concurrency import run_in_threadpool
from app.config import Settings
from app.core.security import Sandbox
from app.core.plugin_registry import PluginRegistry
from app.core.artifact_manager import ArtifactManager
from app.core.job_manager import JobManager
from app.services.store import Store
from app.services.asset_manager import AssetManager
from app.services.case_manager import CaseManager
from app.core.connector_registry import ConnectorRegistry
from app.core.workflow_manager import WorkflowManager

log = logging.getLogger("forensic-hub")


def create_app(settings=None):
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app):
        settings.initialize()
        store = Store(settings)
        sandbox = Sandbox(settings)
        registry = PluginRegistry(settings, sandbox)
        assets = AssetManager(settings, store, sandbox)
        artifacts = ArtifactManager(assets, store)
        app.state.settings = settings
        app.state.store, app.state.sandbox, app.state.registry = store, sandbox, registry
        app.state.assets, app.state.artifacts = assets, artifacts
        app.state.cases = CaseManager(settings, store)
        app.state.jobs = JobManager(settings, store, registry, assets, artifacts, sandbox)
        app.state.connectors = ConnectorRegistry(settings.connectors, registry.plugins)
        app.state.workflows = WorkflowManager(store, assets, app.state.jobs, app.state.connectors)
        for id, plugin in registry.plugins.items():
            if not plugin["available"]:
                continue
            for endpoint in plugin["manifest"]["endpoints"]:

                def make_handler(plugin, endpoint):
                    async def handler(request: Request):
                        payload = (
                            dict(request.query_params) if request.method == "GET" else await request.json()
                        )
                        return await run_in_threadpool(
                            sandbox.run,
                            "route",
                            plugin=plugin,
                            context={"endpoint": endpoint, "request": payload},
                        )

                    return handler

                for route_id in [id, *plugin["manifest"].get("aliases", [])]:
                    app.add_api_route(
                        "/api/plugins/" + route_id + endpoint["path"],
                        make_handler(plugin, endpoint),
                        methods=[endpoint.get("method", "GET").upper()],
                        name=route_id + endpoint["path"],
                    )
        app.openapi_schema = None
        log.info("Forensic Hub avviato: %s plugin, isolamento=%s", len(registry.plugins), sandbox.available)
        yield
        app.state.workflows.shutdown()
        app.state.jobs.shutdown()

    app = FastAPI(title="Forensic Hub", version="1.0.0", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]", "testserver"])

    @app.middleware("http")
    async def guard(request, call_next):
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            origin = request.headers.get("origin")
            if origin and origin != str(request.base_url).rstrip("/"):
                return JSONResponse({"detail": "Origin non consentita"}, status_code=403)
            length = request.headers.get("content-length")
            if request.headers.get("transfer-encoding"):
                return JSONResponse(
                    {"detail": "Usare un corpo con Content-Length, senza transfer encoding"}, status_code=411
                )
            if length is None and request.method != "DELETE":
                return JSONResponse({"detail": "Content-Length richiesto"}, status_code=411)
            limit = (
                settings.max_upload + 1024**2
                if request.url.path == "/api/assets"
                and "multipart/form-data" in request.headers.get("content-type", "")
                else 2 * 1024**2
            )
            if length and (not length.isdigit() or int(length) > limit):
                return JSONResponse({"detail": "Corpo richiesta troppo grande"}, status_code=413)
        response = await call_next(request)
        response.headers.update(
            {
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; frame-src 'none'; base-uri 'self'; form-action 'self'",
            }
        )
        return response

    @app.exception_handler(KeyError)
    async def missing(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=404)

    @app.exception_handler(ValueError)
    async def invalid(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=400)

    @app.exception_handler(RuntimeError)
    async def unavailable(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=503)

    @app.exception_handler(TimeoutError)
    async def timed_out(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=504)

    from app.api.routes import register_routes

    register_routes(app, settings)

    app.mount("/static", StaticFiles(directory=settings.root / "frontend"), name="static")
    return app


app = create_app()
