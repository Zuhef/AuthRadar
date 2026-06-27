"""Tests for authradar.core.auth_flow_detector."""

from __future__ import annotations

from authradar.core.auth_flow_detector import (
    AuthFlowType,
    classify_form,
    classify_link,
    detect_auth_flows,
)
from authradar.core.parsing import FormInput, HtmlForm, ParsedPage


def _form(action: str, *inputs: FormInput, method: str = "post") -> HtmlForm:
    return HtmlForm(action=action, method=method, inputs=tuple(inputs), source_url=action)


def _inp(
    name: str,
    input_type: str = "text",
    *,
    max_length: int | None = None,
    required: bool = False,
) -> FormInput:
    return FormInput(name=name, type=input_type, max_length=max_length, required=required)


def test_classify_login() -> None:
    flow = classify_form(_form("http://t/login", _inp("username"), _inp("password", "password")))
    assert flow is not None
    assert flow.type is AuthFlowType.LOGIN


def test_classify_register_by_confirm_password() -> None:
    flow = classify_form(
        _form(
            "http://t/signup",
            _inp("email", "email"),
            _inp("password", "password"),
            _inp("confirm_password", "password"),
        )
    )
    assert flow is not None
    assert flow.type is AuthFlowType.REGISTER


def test_classify_reset_confirm() -> None:
    flow = classify_form(
        _form("http://t/reset", _inp("token", "hidden"), _inp("password", "password"))
    )
    assert flow is not None
    assert flow.type is AuthFlowType.PASSWORD_RESET_CONFIRM


def test_classify_reset_request() -> None:
    flow = classify_form(_form("http://t/forgot-password", _inp("email", "email")))
    assert flow is not None
    assert flow.type is AuthFlowType.PASSWORD_RESET_REQUEST


def test_classify_otp() -> None:
    flow = classify_form(_form("http://t/verify", _inp("otp", "text", max_length=6)))
    assert flow is not None
    assert flow.type is AuthFlowType.OTP


def test_classify_mfa_by_path() -> None:
    flow = classify_form(_form("http://t/2fa", _inp("code", "text", max_length=6)))
    assert flow is not None
    assert flow.type is AuthFlowType.MFA


def test_classify_change_password() -> None:
    flow = classify_form(
        _form(
            "http://t/account", _inp("old_password", "password"), _inp("new_password", "password")
        )
    )
    assert flow is not None
    assert flow.type is AuthFlowType.CHANGE_PASSWORD


def test_search_form_is_not_auth() -> None:
    assert classify_form(_form("http://t/search", _inp("q"), method="get")) is None


def test_classify_links() -> None:
    logout = classify_link("http://t/logout")
    assert logout is not None
    assert logout.type is AuthFlowType.LOGOUT
    oauth = classify_link("http://t/oauth/authorize?client_id=x&response_type=code")
    assert oauth is not None
    assert oauth.type is AuthFlowType.OAUTH
    assert classify_link("http://t/about") is None


def test_detect_auth_flows_dedupes() -> None:
    page = ParsedPage(
        url="http://t/login",
        forms=(_form("http://t/login", _inp("user"), _inp("pw", "password")),),
        links=("http://t/logout", "http://t/logout"),
    )
    flows = detect_auth_flows([page, page])
    types = [flow.type for flow in flows]
    assert AuthFlowType.LOGIN in types
    assert types.count(AuthFlowType.LOGOUT) == 1
