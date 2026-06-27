"""Tests for authradar.core.endpoint_discovery."""

from __future__ import annotations

from authradar.core.endpoint_discovery import candidate_urls, probe_common_endpoints
from tests.apps import build_vulnerable_app
from tests.helpers import engine_for, make_config


def test_candidate_urls_excludes_seen() -> None:
    config = make_config()
    candidates = candidate_urls(config, {"http://testserver/login"})
    assert "http://testserver/login" not in candidates
    assert "http://testserver/register" in candidates


async def test_probe_finds_existing_endpoints() -> None:
    config = make_config()
    async with engine_for(build_vulnerable_app(), config) as engine:
        result = await probe_common_endpoints(engine, config, set())
    urls = {page.response.url for page in result.pages}
    assert any(url.endswith("/login") for url in urls)
    assert all(page.response.status_code < 400 for page in result.pages)
