"""Optional FastAPI server exposing AuthRadar over HTTP.

Secure by default: the ``/scan`` endpoint is disabled unless the
``AUTHRADAR_API_KEY`` environment variable is set, and every request must then
present a matching ``X-API-Key`` header (compared in constant time). This
prevents an exposed instance from being abused as an open scanning proxy.

Bind the server to localhost unless you have added authentication and network
controls appropriate for your environment.
"""

from __future__ import annotations

import hmac
import os
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, status

from authradar import __version__
from authradar.core.config import ScanConfig
from authradar.core.models import ScanResult
from authradar.engine import run_scan

API_KEY_ENV = "AUTHRADAR_API_KEY"


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


def create_app() -> FastAPI:
    """Build and return the FastAPI application."""
    app = FastAPI(
        title="AuthRadar API",
        version=__version__,
        description="Authentication security auditing as a service.",
    )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.post(
        "/scan",
        response_model=ScanResult,
        dependencies=[Depends(_require_api_key)],
    )
    async def scan(config: ScanConfig) -> ScanResult:
        return await run_scan(config)

    return app
