"""Active discovery of common authentication endpoints.

Complements the crawler by probing a curated list of well-known authentication
paths (``/login``, ``/register``, ``/forgot-password``, ...). Each probe is a
single ``GET`` confined to the target host, so impact is minimal. Paths already
seen by the crawler are skipped.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit, urlunsplit

from authradar.core.config import ScanConfig
from authradar.core.crawler import CrawledPage, CrawlResult, fetch_url
from authradar.core.request_engine import RequestEngine

COMMON_AUTH_PATHS: tuple[str, ...] = (
    "/login",
    "/signin",
    "/sign-in",
    "/log-in",
    "/auth/login",
    "/account/login",
    "/users/login",
    "/user/login",
    "/session/new",
    "/register",
    "/signup",
    "/sign-up",
    "/account/register",
    "/forgot-password",
    "/password/reset",
    "/reset-password",
    "/account/forgot",
    "/logout",
    "/signout",
    "/auth/logout",
    "/api/login",
    "/api/auth/login",
    "/oauth/authorize",
    "/.well-known/openid-configuration",
    "/mfa",
    "/2fa",
    "/verify-otp",
)


def _target_root(target: str) -> str:
    parts = urlsplit(target)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def candidate_urls(config: ScanConfig, already_seen: set[str]) -> list[str]:
    """Absolute URLs for common auth paths not already crawled."""
    root = _target_root(config.target)
    seen_lower = {url.lower() for url in already_seen}
    return [url for path in COMMON_AUTH_PATHS if (url := f"{root}{path}").lower() not in seen_lower]


async def probe_common_endpoints(
    engine: RequestEngine,
    config: ScanConfig,
    already_seen: set[str],
) -> CrawlResult:
    """Probe common auth endpoints, returning those that exist (HTTP < 400)."""
    candidates = candidate_urls(config, already_seen)
    if not candidates:
        return CrawlResult()

    outcomes = await asyncio.gather(*(fetch_url(engine, url) for url in candidates))

    pages: list[CrawledPage] = []
    errors: list[str] = []
    for outcome in outcomes:
        if outcome.error is not None:
            errors.append(outcome.error)
        elif outcome.page is not None and outcome.page.response.status_code < 400:
            pages.append(outcome.page)
    return CrawlResult(pages=tuple(pages), errors=tuple(errors))
