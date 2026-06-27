"""Integration tests for authradar.core.request_engine against ASGI apps."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse, RedirectResponse, Response

from authradar.core.exceptions import ScopeError
from tests.apps import build_vulnerable_app
from tests.helpers import engine_for


def _redirect_app() -> FastAPI:
    app = FastAPI()

    @app.get("/start")
    async def start() -> Response:
        return RedirectResponse("/end", status_code=302)

    @app.get("/end")
    async def end() -> Response:
        return PlainTextResponse("arrived")

    @app.get("/offsite")
    async def offsite() -> Response:
        return RedirectResponse("http://evil.example/x", status_code=302)

    return app


async def test_get_captures_cookies_and_html() -> None:
    async with engine_for(build_vulnerable_app()) as engine:
        resp = await engine.get("http://testserver/login")
    assert resp.status_code == 200
    assert resp.is_html
    assert any(c.name == "SID" for c in resp.cookies)


async def test_out_of_scope_request_raises() -> None:
    async with engine_for(build_vulnerable_app()) as engine:
        assert not engine.in_scope("http://evil.example/")
        with pytest.raises(ScopeError):
            await engine.get("http://evil.example/")


async def test_redirect_followed_in_scope() -> None:
    async with engine_for(_redirect_app()) as engine:
        resp = await engine.get("http://testserver/start")
    assert resp.status_code == 200
    assert resp.body == "arrived"
    assert resp.url.endswith("/end")


async def test_redirect_not_followed_without_flag() -> None:
    async with engine_for(_redirect_app()) as engine:
        resp = await engine.get("http://testserver/start", follow_redirects=False)
    assert resp.status_code == 302


async def test_offsite_redirect_stops_at_boundary() -> None:
    async with engine_for(_redirect_app()) as engine:
        resp = await engine.get("http://testserver/offsite")
    assert resp.status_code == 302


async def test_request_header_redaction() -> None:
    async with engine_for(_redirect_app()) as engine:
        resp = await engine.get("http://testserver/end", headers={"Authorization": "Bearer secret"})
    assert resp.request is not None
    assert resp.request.headers.get("authorization") == "<redacted>"
