"""Adversarial / fuzz-style tests.

These feed malformed and hostile input to the parsing and analysis trust
boundaries and assert that nothing crashes and outputs stay sane.
"""

from __future__ import annotations

import base64

import pytest
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse, Response

from authradar.core.crawler import fetch_url
from authradar.core.exceptions import RequestEngineError
from authradar.core.http import parse_set_cookie, parse_set_cookies
from authradar.core.parsing import parse_html
from authradar.scanner.account_enum_detector import EnumObservation, analyze_enumeration
from authradar.scanner.heuristics import find_jwts
from authradar.scanner.jwt_analyzer import decode_jwt
from authradar.scanner.reset_flow_analyzer import (
    analyze_reset_token,
    estimate_token_entropy_bits,
)
from tests.helpers import engine_for

_HOSTILE_HTML = [
    "",
    "<html",
    "<form><input name=",
    "<a href=>x</a>",
    "<form action='javascript:alert(1)'><input type=password name=p></form>",
    "<" * 5000,
    "<script>" + "a" * 100000 + "</script>",
    "<input name='x' maxlength='not-a-number'>",
    "<meta name content>",
    "\x00\x01\x02 binary garbage \uffff",
    "<form action='http://[::1]:99999/'></form>",
]


def test_parse_html_never_crashes() -> None:
    for html in _HOSTILE_HTML:
        page = parse_html("http://t.example/p", html)
        assert page.url == "http://t.example/p"
        # inline scripts are bounded
        assert all(len(s) <= 200_000 for s in page.inline_scripts)


_HOSTILE_COOKIES = [
    "",
    "=",
    ";;;",
    "Secure",
    "a=b; Max-Age=; SameSite=Bogus; Secure; HttpOnly",
    "name",
    "x=" + "y" * 10000,
    "a=b; SameSite=",
    "  =  ; Path=",
    "k=v; samesite=lax; SECURE",
]


def test_parse_set_cookie_never_crashes() -> None:
    for header in _HOSTILE_COOKIES:
        cookie = parse_set_cookie(header)
        assert cookie.raw == header
    parsed = parse_set_cookies(_HOSTILE_COOKIES)
    assert len(parsed) == len([c for c in _HOSTILE_COOKIES if c])


def test_decode_jwt_rejects_garbage() -> None:
    array_payload = (
        base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
        + "."
        + base64.urlsafe_b64encode(b"[1,2,3]").rstrip(b"=").decode()
        + ".sig"
    )
    hostile = [
        "",
        "...",
        "a.b",
        "!!!.@@@.###",
        "eyJ.eyJ.",
        "a.b.c.d",
        array_payload,
        "x" * 50000,
    ]
    for token in hostile:
        assert decode_jwt(token) is None


def test_find_jwts_handles_large_input() -> None:
    blob = ("eyJ" + "A" * 1000 + "." + "x" * 1000 + " ") * 100
    assert isinstance(find_jwts(blob), list)


def test_reset_token_analysis_edge_cases() -> None:
    assert analyze_reset_token("") is None
    assert estimate_token_entropy_bits("") == 0.0
    # A 1-character token has trivially low entropy and must be flagged weak.
    assert analyze_reset_token("a") is not None


def test_enumeration_handles_empty_bodies() -> None:
    obs = EnumObservation(status_code=200, body="")
    assert analyze_enumeration(obs, obs) is None


def _bad_redirect_app() -> FastAPI:
    app = FastAPI()

    @app.get("/empty")
    async def empty() -> Response:
        return Response(status_code=302)  # 3xx with no Location

    @app.get("/garbage")
    async def garbage() -> Response:
        return PlainTextResponse("x", status_code=302, headers={"location": "://::::"})

    return app


async def test_engine_survives_malformed_redirects() -> None:
    async with engine_for(_bad_redirect_app()) as engine:
        # A 3xx with no Location simply stops manual redirect following.
        empty = await engine.get("http://testserver/empty")
        assert empty.status_code == 302
        # An invalid Location surfaces as a controlled RequestEngineError, never
        # as an unhandled httpx exception.
        with pytest.raises(RequestEngineError):
            await engine.get("http://testserver/garbage")
        # ...and the crawler turns that into a recorded error and keeps going.
        outcome = await fetch_url(engine, "http://testserver/garbage")
        assert outcome.page is None
        assert outcome.error is not None
