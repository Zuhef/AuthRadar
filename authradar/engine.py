"""Scan orchestration.

Ties the pieces together: crawl and probe the target, detect auth flows,
optionally capture browser storage, build a :class:`ScanContext`, run the
selected scanners concurrently (each isolated so one failure cannot abort the
run), and assemble a de-duplicated :class:`ScanResult`.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx

from authradar.core.auth_flow_detector import AuthFlow, AuthFlowType, detect_auth_flows
from authradar.core.browser import collect_browser_storage
from authradar.core.config import ScanConfig
from authradar.core.crawler import crawl
from authradar.core.endpoint_discovery import probe_common_endpoints
from authradar.core.exceptions import AuthRadarError, BrowserUnavailableError
from authradar.core.models import Finding, ScanResult
from authradar.core.plugin_loader import select_scanners
from authradar.core.request_engine import RequestEngine
from authradar.core.scanner_base import BaseScanner, BrowserStorage, ScanContext

_LOGGER = logging.getLogger(__name__)
_MAX_BROWSER_URLS = 5
_BROWSER_FLOW_TYPES = (
    AuthFlowType.LOGIN,
    AuthFlowType.REGISTER,
    AuthFlowType.MFA,
    AuthFlowType.OTP,
)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        if finding.fingerprint not in seen:
            seen.add(finding.fingerprint)
            unique.append(finding)
    return unique


def _browser_urls(config: ScanConfig, flows: list[AuthFlow]) -> list[str]:
    scope = config.scope_hosts()
    urls: dict[str, None] = {config.target: None}
    for flow in flows:
        if flow.type in _BROWSER_FLOW_TYPES:
            urls.setdefault(flow.url, None)
    in_scope = [url for url in urls if _host_in_scope(url, scope)]
    return in_scope[:_MAX_BROWSER_URLS]


def _host_in_scope(url: str, scope: frozenset[str]) -> bool:
    host = urlsplit(url).hostname
    return host is not None and host.lower() in scope


async def _safe_scan(
    scanner: BaseScanner, context: ScanContext
) -> tuple[list[Finding], str | None]:
    try:
        return await scanner.scan(context), None
    except AuthRadarError as exc:
        return [], f"{scanner.id}: {exc}"
    except Exception as exc:
        _LOGGER.exception("scanner %s raised an unexpected error", scanner.id)
        return [], f"{scanner.id}: unexpected error: {exc!r}"


async def _run_scanners(
    scanners: list[BaseScanner], context: ScanContext
) -> tuple[list[Finding], list[str]]:
    outcomes = await asyncio.gather(*(_safe_scan(scanner, context) for scanner in scanners))
    findings: list[Finding] = []
    errors: list[str] = []
    for scanner_findings, error in outcomes:
        findings.extend(scanner_findings)
        if error is not None:
            errors.append(error)
    return findings, errors


async def _collect_storage(
    config: ScanConfig, flows: list[AuthFlow], errors: list[str]
) -> list[BrowserStorage]:
    if not config.use_browser:
        return []
    try:
        return await collect_browser_storage(config, _browser_urls(config, flows))
    except BrowserUnavailableError as exc:
        errors.append(f"browser collection skipped: {exc}")
        return []


async def run_scan(
    config: ScanConfig,
    *,
    scanners: list[BaseScanner] | None = None,
    client: httpx.AsyncClient | None = None,
) -> ScanResult:
    """Run a full authentication audit and return the result.

    ``client`` lets callers (and tests) inject a pre-configured
    :class:`httpx.AsyncClient` (for example one bound to an in-process ASGI app
    via :class:`httpx.ASGITransport`). When provided, the engine does not close
    it; ownership stays with the caller.
    """
    started_at = datetime.now(UTC)
    start = time.perf_counter()
    errors: list[str] = []

    async with RequestEngine(config, client=client) as engine:
        crawl_result = await crawl(engine, config)
        already_seen = {page.response.url for page in crawl_result.pages}
        probe_result = await probe_common_endpoints(engine, config, already_seen)
        errors.extend(crawl_result.errors)
        errors.extend(probe_result.errors)

        pages = list(crawl_result.pages) + list(probe_result.pages)
        responses = [page.response for page in pages]
        parsed = [page.parsed for page in pages if page.parsed is not None]
        flows = detect_auth_flows(parsed)
        storage = await _collect_storage(config, flows, errors)

        context = ScanContext(
            config=config,
            engine=engine,
            responses=responses,
            parsed_pages=parsed,
            auth_flows=flows,
            storage=storage,
        )
        active = select_scanners(config) if scanners is None else scanners
        findings, scan_errors = await _run_scanners(active, context)
        errors.extend(scan_errors)

    duration = time.perf_counter() - start
    return ScanResult(
        target=config.target,
        started_at=started_at,
        finished_at=datetime.now(UTC),
        duration_s=duration,
        findings=_dedupe(findings),
        scanners_run=sorted(scanner.id for scanner in active),
        pages_crawled=len(responses),
        errors=errors,
    )
