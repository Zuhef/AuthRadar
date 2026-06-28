"""Tests for the FastAPI server: health, auth gating, scanners, UI and jobs."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import httpx
import pytest

from authradar.api import API_KEY_ENV, create_app
from authradar.core.config import ScanConfig
from authradar.core.models import ScanResult
from authradar.jobs import JobStore

_BASE = "http://api.test"
_KEY = "s3cret"


def _client(job_store: JobStore | None = None) -> httpx.AsyncClient:
    app = create_app(job_store=job_store)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=_BASE)


async def _ok_runner(config: ScanConfig) -> ScanResult:
    now = datetime.now(UTC)
    return ScanResult(
        target=config.target,
        started_at=now,
        finished_at=now,
        duration_s=0.01,
        findings=[],
        scanners_run=["login_detector"],
        pages_crawled=1,
    )


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
    monkeypatch.setenv(API_KEY_ENV, _KEY)
    async with _client() as client:
        response = await client.post(
            "/scan",
            headers={"X-API-Key": "wrong"},
            json={"target": "https://example.com"},
        )
    assert response.status_code == 401


async def test_scanners_listed() -> None:
    async with _client() as client:
        response = await client.get("/scanners")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list) and data
    ids = {item["id"] for item in data}
    assert "login_detector" in ids
    assert all({"id", "name", "category", "description"} <= set(item) for item in data)


async def test_index_redirects_to_ui() -> None:
    async with _client() as client:
        response = await client.get("/")
    assert response.status_code in (307, 308)
    assert response.headers["location"] == "/ui/"


async def test_ui_is_served() -> None:
    async with _client() as client:
        response = await client.get("/ui/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "AuthRadar" in response.text


async def test_scan_jobs_disabled_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(API_KEY_ENV, raising=False)
    async with _client() as client:
        response = await client.post("/scan/jobs", json={"target": "https://example.com"})
    assert response.status_code == 503


async def test_unknown_job_returns_404(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(API_KEY_ENV, _KEY)
    async with _client() as client:
        response = await client.get("/scan/jobs/missing", headers={"X-API-Key": _KEY})
    assert response.status_code == 404


async def test_scan_job_lifecycle(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(API_KEY_ENV, _KEY)
    store = JobStore(runner=_ok_runner)
    headers = {"X-API-Key": _KEY}

    async with _client(job_store=store) as client:
        created = await client.post(
            "/scan/jobs", headers=headers, json={"target": "https://example.com"}
        )
        assert created.status_code == 202
        job_id = created.json()["id"]

        data: dict[str, object] = {}
        for _ in range(50):
            polled = await client.get(f"/scan/jobs/{job_id}", headers=headers)
            assert polled.status_code == 200
            data = polled.json()
            if data["status"] in ("completed", "failed"):
                break
            await asyncio.sleep(0.02)

        assert data["status"] == "completed"
        result = data["result"]
        assert isinstance(result, dict)
        assert result["target"] == "https://example.com"

        listed = await client.get("/scan/jobs", headers=headers)
    assert listed.status_code == 200
    assert any(job["id"] == job_id for job in listed.json())
