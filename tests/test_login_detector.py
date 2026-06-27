"""Tests for authradar.scanner.login_detector."""

from __future__ import annotations

from authradar.core.parsing import FormInput, HtmlForm
from authradar.scanner.login_detector import analyze_login_security


def _form(action: str, method: str, source: str) -> HtmlForm:
    return HtmlForm(
        action=action,
        method=method,
        inputs=(FormInput(name="username"), FormInput(name="password", type="password")),
        source_url=source,
    )


def test_http_login_flagged() -> None:
    ids = {f.id for f in analyze_login_security(_form("http://t/login", "post", "http://t/login"))}
    assert "AR-LOGIN-001" in ids


def test_https_post_login_clean() -> None:
    assert analyze_login_security(_form("https://t/login", "post", "https://t/login")) == []


def test_get_login_flagged() -> None:
    ids = {f.id for f in analyze_login_security(_form("https://t/login", "get", "https://t/login"))}
    assert "AR-LOGIN-002" in ids


def test_http_page_https_action_still_flagged() -> None:
    ids = {f.id for f in analyze_login_security(_form("https://t/login", "post", "http://t/login"))}
    assert "AR-LOGIN-001" in ids
