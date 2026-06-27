"""Integration tests for authradar.core.crawler."""

from __future__ import annotations

from authradar.core.crawler import crawl
from tests.apps import build_vulnerable_app
from tests.helpers import engine_for, make_config


async def test_crawl_discovers_linked_pages() -> None:
    config = make_config(max_pages=10, max_depth=2)
    async with engine_for(build_vulnerable_app(), config) as engine:
        result = await crawl(engine, config)
    urls = {page.response.url for page in result.pages}
    assert any("/login" in url for url in urls)
    assert len(result.parsed_pages) >= 1


async def test_crawl_respects_max_pages() -> None:
    config = make_config(max_pages=1, max_depth=3)
    async with engine_for(build_vulnerable_app(), config) as engine:
        result = await crawl(engine, config)
    assert len(result.pages) == 1
