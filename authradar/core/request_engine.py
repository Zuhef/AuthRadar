"""Asynchronous HTTP request engine.

This is the only component that performs network I/O. It wraps
:class:`httpx.AsyncClient` and adds:

* host-allowlist scope enforcement on every hop (defence against
  attacker-controlled redirects escaping the authorised target);
* manual redirect following so scope is re-checked at each hop;
* bounded concurrency via a semaphore;
* explicit, per-request cookie control (the implicit client cookie jar is
  disabled so probes never bleed session state into one another);
* normalisation into immutable :class:`CapturedResponse` objects;
* redaction of sensitive request headers in captured snapshots.
"""

from __future__ import annotations

import asyncio
from types import TracebackType
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from authradar.core.config import ScanConfig
from authradar.core.exceptions import RequestEngineError, ScopeError
from authradar.core.http import CapturedRequest, CapturedResponse, parse_set_cookies

_MAX_BODY_CHARS = 2_000_000
_REDACTED = "<redacted>"
_SENSITIVE_HEADERS = frozenset({"authorization", "cookie", "proxy-authorization"})
_METHOD_PRESERVING_REDIRECTS = frozenset({307, 308})


class _NoStoreCookies(httpx.Cookies):
    """A cookie jar that neither stores response cookies nor injects them.

    AuthRadar manages cookies explicitly per request so that scanner probes have
    deterministic, isolated session state. Disabling the implicit jar prevents
    httpx from overriding our explicit ``Cookie`` header.
    """

    def extract_cookies(self, _response: httpx.Response) -> None:
        return None

    def set_cookie_header(self, _request: httpx.Request) -> None:
        return None


def _host_of(url: str) -> str:
    host = urlsplit(url).hostname
    return host.lower() if host else ""


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        key: (_REDACTED if key.lower() in _SENSITIVE_HEADERS else value)
        for key, value in headers.items()
    }


def _with_cookie_header(
    headers: dict[str, str] | None, cookies: dict[str, str] | None
) -> dict[str, str] | None:
    if not cookies:
        return headers
    merged = dict(headers or {})
    merged["Cookie"] = "; ".join(f"{name}={value}" for name, value in cookies.items())
    return merged


def _safe_elapsed_ms(response: httpx.Response) -> float:
    try:
        return response.elapsed.total_seconds() * 1000.0
    except RuntimeError:
        # ``elapsed`` is unavailable on a response that was not fully read.
        return 0.0


class RequestEngine:
    """Scope-aware async HTTP client returning :class:`CapturedResponse`."""

    def __init__(self, config: ScanConfig, client: httpx.AsyncClient | None = None) -> None:
        self._config = config
        self._scope = config.scope_hosts()
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            follow_redirects=False,
            verify=config.verify_tls,
            timeout=config.timeout_s,
            headers={"User-Agent": config.user_agent},
        )
        # Disable the implicit cookie jar; AuthRadar controls cookies per request.
        self._client.cookies = _NoStoreCookies()
        self._semaphore = asyncio.Semaphore(config.concurrency)

    async def __aenter__(self) -> RequestEngine:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the underlying client if this engine owns it."""
        if self._owns_client:
            await self._client.aclose()

    def in_scope(self, url: str) -> bool:
        """Return whether ``url`` targets an allowed host."""
        return _host_of(url) in self._scope

    def _ensure_scope(self, url: str) -> None:
        if not self.in_scope(url):
            msg = f"refusing out-of-scope request to host {_host_of(url)!r}"
            raise ScopeError(msg)

    async def _send_once(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None,
        data: dict[str, str] | None,
        json: Any,
    ) -> httpx.Response:
        async with self._semaphore:
            try:
                return await self._client.request(
                    method, url, headers=headers, data=data, json=json
                )
            except httpx.HTTPError as exc:
                msg = f"request to {url} failed: {exc!r}"
                raise RequestEngineError(msg) from exc

    def _capture(self, response: httpx.Response) -> CapturedResponse:
        merged: dict[str, str] = {}
        for key, value in response.headers.multi_items():
            lower = key.lower()
            if lower == "set-cookie":
                continue
            merged[lower] = f"{merged[lower]}, {value}" if lower in merged else value

        set_cookie = tuple(response.headers.get_list("set-cookie"))
        try:
            body = response.text[:_MAX_BODY_CHARS]
        except (UnicodeDecodeError, httpx.HTTPError):
            body = ""

        req = response.request
        captured_request = CapturedRequest(
            method=req.method,
            url=str(req.url),
            headers=_redact_headers(dict(req.headers)),
            body=None,
        )
        return CapturedResponse(
            url=str(response.url),
            status_code=response.status_code,
            headers=merged,
            set_cookie=set_cookie,
            cookies=parse_set_cookies(list(set_cookie)),
            body=body,
            elapsed_ms=_safe_elapsed_ms(response),
            request=captured_request,
        )

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        json: Any = None,
        cookies: dict[str, str] | None = None,
        follow_redirects: bool | None = None,
    ) -> CapturedResponse:
        """Send a request, enforcing scope at every redirect hop.

        Cookies are sent via an explicit ``Cookie`` header. Redirects to
        out-of-scope hosts are not followed; the 3xx response is returned
        instead. Raises :class:`ScopeError` if the initial URL is out of scope
        and :class:`RequestEngineError` on transport failure.
        """
        self._ensure_scope(url)
        effective_headers = _with_cookie_header(headers, cookies)
        allow_redirects = (
            self._config.follow_redirects if follow_redirects is None else follow_redirects
        )
        current_url = url
        hops = 0
        response = await self._send_once(
            method, current_url, headers=effective_headers, data=data, json=json
        )

        while allow_redirects and response.is_redirect and hops < self._config.max_redirects:
            location = response.headers.get("location")
            if not location:
                break
            next_url = urljoin(current_url, location)
            if not self.in_scope(next_url):
                # Stop at the boundary rather than escaping scope.
                break
            hops += 1
            current_url = next_url
            preserve = response.status_code in _METHOD_PRESERVING_REDIRECTS
            response = await self._send_once(
                method if preserve else "GET",
                current_url,
                headers=effective_headers,
                data=data if preserve else None,
                json=json if preserve else None,
            )

        return self._capture(response)

    async def get(self, url: str, **kwargs: Any) -> CapturedResponse:
        """Convenience wrapper for ``GET``."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> CapturedResponse:
        """Convenience wrapper for ``POST``."""
        return await self.request("POST", url, **kwargs)
