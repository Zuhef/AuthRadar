"""Tests for the FastAPI server's health and authentication gating."""

from __future__ import annotations

import httpx
import pytest

from authradar.api import API_KEY_ENV, create_app

_BASE = "http://api.test"


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url=_BASE)


async def test_health() -> None:
    async with _client() as client:
        response = await client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


async def test_scan_disabled_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(API_KEY_ENV, raising=False)
    async with _client() as client:
        response = await client.post("/scan", json={"target": "https://example.com"})
    assert response.status_code == 503


async def test_scan_rejects_bad_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(API_KEY_ENV, "s3cret")
    async with _client() as client:
        response = await client.post(
            "/scan",
            headers={"X-API-Key": "wrong"},
            json={"target": "https://example.com"},
        )
    assert response.status_code == 401
