"""Optional FastAPI server exposing AuthRadar over HTTP and a web UI.

Secure by default: every scanning endpoint is disabled unless the
``AUTHRADAR_API_KEY`` environment variable is set, and every such request must
then present a matching ``X-API-Key`` header (compared in constant time). This
prevents an exposed instance from being abused as an open scanning proxy.

Endpoints:

* ``GET  /health``           — liveness/version probe (open).
* ``GET  /scanners``         — list available scanners (open, metadata only).
* ``POST /scan``             — run a scan synchronously, return the result (keyed).
* ``POST /scan/jobs``        — start a scan as a background job (keyed).
* ``GET  /scan/jobs``        — list tracked jobs (keyed).
* ``GET  /scan/jobs/{id}``   — poll a job's status/result (keyed).
* ``GET  /ui/``              — single-page web dashboard (open static assets).

The ``/scan`` and ``/scan/jobs*`` endpoints are protected; serving the static
UI is not, because the UI cannot do anything without a key the operator pastes
in at runtime. Bind the server to localhost unless you have added network
controls appropriate for your environment.
"""

from __future__ import annotations

import hmac
import os
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict

from authradar import __version__
from authradar.core.config import ScanConfig
from authradar.core.models import ScanResult
from authradar.core.plugin_loader import load_builtin_scanners, load_plugin_scanners
from authradar.core.scanner_base import registered_scanners
from authradar.engine import run_scan
from authradar.jobs import JobStore, ScanJob

API_KEY_ENV = "AUTHRADAR_API_KEY"
_WEB_DIR = Path(__file__).parent / "web"


class ScannerInfo(BaseModel):
    """Public metadata describing a registered scanner."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    category: str
    description: str


def _require_api_key(x_api_key: Annotated[str | None, Header()] = None) -> None:
    """Reject the request unless a configured API key is presented."""
    expected = os.environ.get(API_KEY_ENV)
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"scanning disabled: set {API_KEY_ENV} to enable the API",
        )
    if not x_api_key or not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing X-API-Key",
        )


def _list_scanner_info() -> list[ScannerInfo]:
    """Return metadata for every registered scanner, sorted by id."""
    load_builtin_scanners()
    load_plugin_scanners()
    return [
        ScannerInfo(
            id=scanner_id,
            name=scanner_cls.name,
            category=scanner_cls.category.value,
            description=scanner_cls.description,
        )
        for scanner_id, scanner_cls in sorted(registered_scanners().items())
    ]


def create_app(*, job_store: JobStore | None = None) -> FastAPI:
    """Build and return the FastAPI application."""
    app = FastAPI(
        title="AuthRadar API",
        version=__version__,
        description="Authentication security auditing as a service.",
    )
    store = job_store or JobStore()
    keyed = [Depends(_require_api_key)]

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/scanners", response_model=list[ScannerInfo])
    async def scanners() -> list[ScannerInfo]:
        return _list_scanner_info()

    @app.post("/scan", response_model=ScanResult, dependencies=keyed)
    async def scan(config: ScanConfig) -> ScanResult:
        return await run_scan(config)

    @app.post(
        "/scan/jobs",
        response_model=ScanJob,
        status_code=status.HTTP_202_ACCEPTED,
        dependencies=keyed,
    )
    async def create_scan_job(config: ScanConfig) -> ScanJob:
        return await store.create(config)

    @app.get("/scan/jobs", response_model=list[ScanJob], dependencies=keyed)
    async def list_scan_jobs() -> list[ScanJob]:
        return store.list_jobs()

    @app.get("/scan/jobs/{job_id}", response_model=ScanJob, dependencies=keyed)
    async def get_scan_job(job_id: str) -> ScanJob:
        job = store.get(job_id)
        if job is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"unknown job id {job_id!r}",
            )
        return job

    if _WEB_DIR.is_dir():
        app.mount("/ui", StaticFiles(directory=_WEB_DIR, html=True), name="ui")

        @app.get("/", include_in_schema=False)
        async def index() -> RedirectResponse:
            return RedirectResponse(url="/ui/")

    return app
