"""Optional browser-based collection of client-side storage.

Uses Playwright (if installed, with a browser binary) to load in-scope pages in
a headless browser and read ``localStorage`` / ``sessionStorage``. This lets the
JWT scanner detect tokens kept in web storage. Entirely optional: if Playwright
or the browser binary is unavailable, :class:`BrowserUnavailableError` is raised
and the caller continues without storage data.
"""

from __future__ import annotations

import logging
from typing import Any

from authradar.core.config import ScanConfig
from authradar.core.exceptions import BrowserUnavailableError
from authradar.core.scanner_base import BrowserStorage

_LOGGER = logging.getLogger(__name__)
_DUMP_STORAGE_JS = "() => Object.assign({}, window.localStorage)"
_DUMP_SESSION_JS = "() => Object.assign({}, window.sessionStorage)"


def _coerce_str_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key): str(val) for key, val in value.items()}


async def collect_browser_storage(config: ScanConfig, urls: list[str]) -> list[BrowserStorage]:
    """Open each URL in a headless browser and capture web storage.

    Raises :class:`BrowserUnavailableError` if Playwright or a browser binary is
    not available.
    """
    try:
        from playwright.async_api import async_playwright  # noqa: PLC0415 - optional lazy import
    except ImportError as exc:  # pragma: no cover - exercised only without playwright
        msg = "playwright is not installed; install it and run 'playwright install chromium'"
        raise BrowserUnavailableError(msg) from exc

    timeout_ms = config.timeout_s * 1000.0
    results: list[BrowserStorage] = []
    async with async_playwright() as playwright:
        try:
            browser = await playwright.chromium.launch(headless=True)
        except Exception as exc:
            msg = f"could not launch a browser (run 'playwright install chromium'): {exc}"
            raise BrowserUnavailableError(msg) from exc
        try:
            for url in urls:
                results.append(await _capture_one(browser, url, timeout_ms))
        finally:
            await browser.close()
    return results


async def _capture_one(browser: Any, url: str, timeout_ms: float) -> BrowserStorage:
    page = await browser.new_page()
    try:
        await page.goto(url, wait_until="load", timeout=timeout_ms)
        local = _coerce_str_map(await page.evaluate(_DUMP_STORAGE_JS))
        session = _coerce_str_map(await page.evaluate(_DUMP_SESSION_JS))
        return BrowserStorage(url=url, local_storage=local, session_storage=session)
    finally:
        await page.close()
