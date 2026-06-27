"""Asynchronous, scope-bounded web crawler.

Performs a breadth-first crawl of the target, level by level, fetching each
frontier concurrently (bounded by the engine's semaphore). Only in-scope,
previously unseen URLs are enqueued, and the crawl is capped by ``max_pages``
and ``max_depth``.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from urllib.parse import urldefrag

from pydantic import BaseModel, ConfigDict

from authradar.core.config import ScanConfig
from authradar.core.exceptions import AuthRadarError
from authradar.core.http import CapturedResponse
from authradar.core.parsing import ParsedPage, parse_html
from authradar.core.request_engine import RequestEngine


class CrawledPage(BaseModel):
    """A fetched response paired with its parsed structure (if HTML)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    response: CapturedResponse
    parsed: ParsedPage | None = None


class CrawlResult(BaseModel):
    """Aggregate output of a crawl."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    pages: tuple[CrawledPage, ...] = ()
    errors: tuple[str, ...] = ()

    @property
    def parsed_pages(self) -> list[ParsedPage]:
        """All successfully parsed HTML pages."""
        return [page.parsed for page in self.pages if page.parsed is not None]

    @property
    def responses(self) -> list[CapturedResponse]:
        """All captured responses."""
        return [page.response for page in self.pages]


@dataclass(slots=True)
class FetchOutcome:
    """The result of fetching a single URL: a page or an error message."""

    page: CrawledPage | None
    error: str | None


def canonicalize(url: str) -> str:
    """Drop the fragment so URLs that differ only by ``#...`` are deduplicated."""
    return urldefrag(url)[0]


async def fetch_url(engine: RequestEngine, url: str) -> FetchOutcome:
    """Fetch one URL, parsing HTML, capturing any error instead of raising."""
    try:
        response = await engine.get(url)
    except AuthRadarError as exc:
        return FetchOutcome(page=None, error=f"{url}: {exc}")
    parsed = parse_html(response.url, response.body) if response.is_html else None
    return FetchOutcome(page=CrawledPage(response=response, parsed=parsed), error=None)


async def crawl(engine: RequestEngine, config: ScanConfig) -> CrawlResult:
    """Crawl ``config.target`` and return discovered pages and errors."""
    visited: set[str] = set()
    frontier: list[str] = [canonicalize(config.target)]
    pages: list[CrawledPage] = []
    errors: list[str] = []
    depth = 0

    while frontier and len(visited) < config.max_pages and depth <= config.max_depth:
        batch: list[str] = []
        for raw in frontier:
            url = canonicalize(raw)
            if url in visited:
                continue
            visited.add(url)
            batch.append(url)
            if len(visited) >= config.max_pages:
                break

        if not batch:
            break

        outcomes = await asyncio.gather(*(fetch_url(engine, url) for url in batch))

        next_frontier: list[str] = []
        for outcome in outcomes:
            if outcome.error is not None:
                errors.append(outcome.error)
                continue
            if outcome.page is None:
                continue
            pages.append(outcome.page)
            if depth < config.max_depth and outcome.page.parsed is not None:
                for link in outcome.page.parsed.links:
                    canonical = canonicalize(link)
                    if canonical not in visited and engine.in_scope(canonical):
                        next_frontier.append(canonical)

        frontier = next_frontier
        depth += 1

    return CrawlResult(pages=tuple(pages), errors=tuple(errors))
