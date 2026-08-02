"""FastAPI application factory for the Lucin platform (50_ §2.1, §2.3).

Run:
    uvicorn control_plane.api.app:app --reload --port 8080

The app mounts the /v1 routers and a bare GET /healthz. Auth/DB/RLS wiring lives
in deps.py (currently scaffolded — most handlers raise NotImplementedError until
Stage 1). This app IMPORTS but does not run without `fastapi` installed
(absent in the scaffold venv — see control_plane/README.md).
"""

from __future__ import annotations

from fastapi import FastAPI

from control_plane import __version__
from control_plane.api.routers import auth, findings, orgs, scans, telemetry
from control_plane.api.schemas import Health


def create_app() -> FastAPI:
    app = FastAPI(
        title="Lucin Platform API",
        version=__version__,
        description=(
            "Hosted control plane around the Lucin OSS engine. "
            "SCAFFOLD — see control_plane/README.md."
        ),
        docs_url="/docs",
        openapi_url="/openapi.json",  # the SDK + dashboard are generated from this
    )

    @app.get("/healthz", response_model=Health, tags=["meta"])
    async def healthz() -> Health:
        """Liveness probe — no auth, no DB. Always safe to call."""
        return Health(version=__version__)

    # /v1 surface (50_ §2.3)
    app.include_router(auth.router)
    app.include_router(scans.router)
    app.include_router(findings.router)
    app.include_router(telemetry.router)
    app.include_router(orgs.router)

    return app


app = create_app()
