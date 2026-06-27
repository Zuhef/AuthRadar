"""Tests for authradar.scanner.csrf_auth_analyzer."""

from __future__ import annotations

from authradar.core.auth_flow_detector import AuthFlowType
from authradar.core.http import ParsedCookie, SameSite
from authradar.core.parsing import FormInput, HtmlForm
from authradar.scanner.csrf_auth_analyzer import (
    analyze_csrf_protection,
    cookies_provide_samesite_protection,
    has_csrf_field,
)


def _form(*inputs: FormInput, method: str = "post") -> HtmlForm:
    return HtmlForm(
        action="http://t/login", method=method, inputs=tuple(inputs), source_url="http://t/login"
    )


def test_missing_csrf_flagged() -> None:
    form = _form(FormInput(name="username"), FormInput(name="password", type="password"))
    finding = analyze_csrf_protection(form, flow_type=AuthFlowType.LOGIN, samesite_protected=False)
    assert finding is not None
    assert finding.id == "AR-CSRF-001"


def test_csrf_field_present() -> None:
    form = _form(
        FormInput(name="csrf_token", type="hidden"), FormInput(name="password", type="password")
    )
    assert has_csrf_field(form)
    assert (
        analyze_csrf_protection(form, flow_type=AuthFlowType.LOGIN, samesite_protected=False)
        is None
    )


def test_samesite_protection_suppresses() -> None:
    form = _form(FormInput(name="password", type="password"))
    assert (
        analyze_csrf_protection(form, flow_type=AuthFlowType.LOGIN, samesite_protected=True) is None
    )


def test_get_form_not_flagged() -> None:
    form = _form(FormInput(name="password", type="password"), method="get")
    assert (
        analyze_csrf_protection(form, flow_type=AuthFlowType.LOGIN, samesite_protected=False)
        is None
    )


def test_cookie_samesite_detection() -> None:
    assert cookies_provide_samesite_protection(
        [ParsedCookie(name="SID", value="x", same_site=SameSite.LAX)]
    )
    assert not cookies_provide_samesite_protection([ParsedCookie(name="SID", value="x")])
    assert not cookies_provide_samesite_protection(
        [ParsedCookie(name="theme", value="x", same_site=SameSite.STRICT)]
    )
