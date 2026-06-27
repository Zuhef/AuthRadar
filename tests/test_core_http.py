"""Tests for authradar.core.http."""

from __future__ import annotations

from authradar.core.http import CapturedResponse, SameSite, parse_set_cookie, parse_set_cookies


def test_parse_full_cookie() -> None:
    cookie = parse_set_cookie("SID=abc123; Path=/; Domain=ex.com; HttpOnly; Secure; SameSite=Lax")
    assert cookie.name == "SID"
    assert cookie.value == "abc123"
    assert cookie.secure
    assert cookie.http_only
    assert cookie.same_site is SameSite.LAX
    assert cookie.path == "/"
    assert cookie.domain == "ex.com"


def test_parse_minimal_cookie() -> None:
    cookie = parse_set_cookie("token=xyz")
    assert cookie.name == "token"
    assert cookie.value == "xyz"
    assert not cookie.secure
    assert not cookie.http_only
    assert cookie.same_site is None


def test_parse_samesite_none_and_max_age() -> None:
    cookie = parse_set_cookie("a=b; Max-Age=3600; SameSite=None")
    assert cookie.same_site is SameSite.NONE
    assert cookie.max_age == 3600


def test_parse_bad_max_age_ignored() -> None:
    cookie = parse_set_cookie("a=b; Max-Age=not-a-number")
    assert cookie.max_age is None


def test_parse_malformed_does_not_raise() -> None:
    assert parse_set_cookie("=; ;; Secure").secure
    nameless = parse_set_cookie("justaname")
    assert nameless.name == "justaname"
    assert nameless.value == ""


def test_parse_set_cookies_skips_empty() -> None:
    cookies = parse_set_cookies(["x=1; Secure", "", "y=2"])
    assert [c.name for c in cookies] == ["x", "y"]


def test_captured_response_helpers() -> None:
    response = CapturedResponse(
        url="https://example.com/a",
        status_code=200,
        headers={"content-type": "text/html; charset=utf-8"},
    )
    assert response.is_https
    assert response.is_html
    assert response.content_type == "text/html"
    assert response.header("Content-Type") == "text/html; charset=utf-8"


def test_captured_response_http_non_html() -> None:
    response = CapturedResponse(url="http://example.com", status_code=204, headers={})
    assert not response.is_https
    assert not response.is_html
    assert response.header("missing") is None
