"""Stage 1: local, offline API using the existing inventory and read routes.

No worker, scanner, shell, telemetry pipeline, or enforcement module is imported.
Online operation stays unavailable until scope and authorization gates are tested.
"""
from contextlib import asynccontextmanager
import ipaddress
from fastapi import FastAPI, Request, HTTPException
from starlette.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from .config import settings
from .secret_config import load_secret_key
load_secret_key()  # Fail before database creation or router initialization.
from .database import init_db
from .auth import authorize_header
from .routers import auth, alerts_db, devices_db, stats, reports, reports_db

if not settings.offline_mode:
    raise RuntimeError("Online mode is unavailable in Stage 1; use OFFLINE_MODE=true.")

READ_PATHS = {
    "/", "/health", "/docs", "/docs/oauth2-redirect", "/openapi.json", "/redoc",
    "/auth/me", "/devices/", "/alerts/", "/stats/dashboard",
    "/stats/network-activity", "/stats/threat-trends", "/reports/list",
    "/reports-db/incidents", "/reports-db/isolation/details",
    "/reports-db/observation/details",
}
AUTH_WRITES = {"/auth/signup", "/auth/login", "/auth/logout"}


@asynccontextmanager
async def lifespan(app):
    init_db()
    yield


def create_app():
    app = FastAPI(
        title="AVIGHNA Offline Preview", version="3.0.0",
        description="Stage 1 offline baseline. No live collection or containment.",
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def offline_boundary(request: Request, call_next):
        # This preview is intentionally local-only pending the Stage 3 API audit.
        host = request.client.host if request.client else ""
        try:
            local = ipaddress.ip_address(host).is_loopback
        except ValueError:
            local = False
        if not local:
            return JSONResponse({"detail": "Offline preview is local-only."}, status_code=403)
        path = request.url.path
        readable = path in READ_PATHS or (
            path.startswith("/reports/download/") and path.rsplit("/", 1)[-1].isdigit()
        )
        allowed = (
            request.method in {"GET", "HEAD"} and readable
            or request.method == "POST" and path in AUTH_WRITES
            or request.method == "OPTIONS"
        )
        public = (request.method in {"GET", "HEAD"} and path in {"/", "/health"}) or (
            request.method == "POST" and path in {"/auth/login", "/auth/signup"}
        ) or request.method == "OPTIONS"
        if not public:
            permission = "read" if readable or path == "/auth/logout" else "admin"
            try:
                await run_in_threadpool(authorize_header, request.headers.get("Authorization", ""), permission)
            except HTTPException as error:
                return JSONResponse({"detail": error.detail}, status_code=error.status_code, headers=error.headers)
        if not allowed:
            return JSONResponse({
                "detail": "Unavailable in offline mode. No action was attempted.",
                "mode": "offline",
            }, status_code=503)
        response = await call_next(request)
        response.headers["X-AVIGHNA-Mode"] = "offline"
        return response

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
        allow_credentials=True, allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

    @app.get("/")
    def root():
        return {"name": "AVIGHNA", "version": "3.0.0", "status": "offline",
                "monitoring": False, "enforcement": False}

    @app.get("/health")
    def health():
        return {"status": "ok", "mode": "offline", "collection_enabled": False,
                "enforcement_enabled": False, "shell_enabled": False,
                "note": "API availability is not a device-security verdict."}

    for router, prefix in (
        (auth.router, "/auth"), (alerts_db.router, "/alerts"),
        (devices_db.router, "/devices"), (stats.router, "/stats"),
        (reports.router, "/reports"), (reports_db.router, "/reports-db"),
    ):
        app.include_router(router, prefix=prefix)
    return app


app = create_app()
