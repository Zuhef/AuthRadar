"""Tests for authradar.scanner.session_checker pure analysis."""

from __future__ import annotations

from authradar.core.http import ParsedCookie, SameSite
from authradar.core.parsing import FormInput, HtmlForm
from authradar.scanner.heuristics import build_login_payload
from authradar.scanner.session_checker import (
    analyze_cookie_security,
    analyze_logout_invalidation,
    analyze_session_fixation,
    extract_session_cookie,
)


def test_missing_all_flags_https() -> None:
    ids = {
        f.id for f in analyze_cookie_security([ParsedCookie(name="SID", value="x")], is_https=True)
    }
    assert {"AR-COOKIE-001", "AR-COOKIE-002", "AR-COOKIE-003"} <= ids


def test_secure_flag_only_on_https() -> None:
    ids = {
        f.id for f in analyze_cookie_security([ParsedCookie(name="SID", value="x")], is_https=False)
    }
    assert "AR-COOKIE-001" not in ids
    assert "AR-COOKIE-002" in ids


def test_samesite_none_without_secure() -> None:
    cookie = ParsedCookie(name="data", value="x", same_site=SameSite.NONE, secure=False)
    ids = {f.id for f in analyze_cookie_security([cookie], is_https=True)}
    assert "AR-COOKIE-004" in ids


def test_csrf_cookie_allows_js_access() -> None:
    cookie = ParsedCookie(name="csrftoken", value="x", secure=True, same_site=SameSite.LAX)
    ids = {f.id for f in analyze_cookie_security([cookie], is_https=True)}
    assert "AR-COOKIE-002" not in ids


def test_secure_cookie_clean() -> None:
    cookie = ParsedCookie(
        name="SID", value="x", secure=True, http_only=True, same_site=SameSite.LAX
    )
    assert analyze_cookie_security([cookie], is_https=True) == []


def test_session_fixation() -> None:
    fixation = analyze_session_fixation("same", "same")
    assert fixation is not None
    assert fixation.id == "AR-SESSION-001"
    assert analyze_session_fixation("a", "b") is None
    assert analyze_session_fixation(None, None) is None


def test_logout_invalidation() -> None:
    broken = analyze_logout_invalidation(authenticated_after_logout=True)
    assert broken is not None
    assert broken.id == "AR-SESSION-002"
    assert analyze_logout_invalidation(authenticated_after_logout=False) is None


def test_extract_session_cookie() -> None:
    cookies = [ParsedCookie(name="theme", value="dark"), ParsedCookie(name="SID", value="abc")]
    found = extract_session_cookie(cookies)
    assert found is not None
    assert found.name == "SID"
    assert extract_session_cookie([ParsedCookie(name="theme", value="x")]) is None


def test_build_login_payload_preserves_hidden_fields() -> None:
    form = HtmlForm(
        action="http://t/login",
        method="post",
        inputs=(
            FormInput(name="csrf", type="hidden", value="tok"),
            FormInput(name="username", type="text"),
            FormInput(name="password", type="password"),
        ),
        source_url="http://t/login",
    )
    data = build_login_payload(form, "u", "p", username_field="username", password_field="password")
    assert data == {"csrf": "tok", "username": "u", "password": "p"}
