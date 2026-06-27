"""Reusable helpers for tests (config, in-process engine, sample flows)."""

from __future__ import annotations

from typing import Any

import httpx
from fastapi import FastAPI

from authradar.core.auth_flow_detector import AuthFlow, AuthFlowType
from authradar.core.config import ScanConfig
from authradar.core.parsing import FormInput, HtmlForm
from authradar.core.request_engine import RequestEngine

TARGET = "http://testserver"


def make_config(**overrides: Any) -> ScanConfig:
    """Build a ScanConfig with test-friendly defaults."""
    params: dict[str, Any] = {
        "target": TARGET,
        "max_pages": 20,
        "max_depth": 2,
        "concurrency": 4,
        "timeout_s": 5.0,
        "probe_attempts": 8,
    }
    params.update(overrides)
    return ScanConfig(**params)


def asgi_client(app: FastAPI) -> httpx.AsyncClient:
    """An httpx client that routes all requests to ``app`` in-process."""
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url=TARGET, follow_redirects=False)


def engine_for(app: FastAPI, config: ScanConfig | None = None) -> RequestEngine:
    """A RequestEngine bound to an in-process ASGI app."""
    return RequestEngine(config or make_config(), client=asgi_client(app))


def login_flow(action: str = f"{TARGET}/login") -> AuthFlow:
    """A LOGIN AuthFlow matching the test apps' login form."""
    form = HtmlForm(
        action=action,
        method="post",
        inputs=(
            FormInput(name="username", type="text"),
            FormInput(name="password", type="password"),
        ),
        source_url=action,
    )
    return AuthFlow(type=AuthFlowType.LOGIN, url=action, method="post", form=form)
