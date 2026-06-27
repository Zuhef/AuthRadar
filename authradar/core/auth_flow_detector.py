"""Heuristic detection of authentication flows from parsed pages.

Given the structural extract of crawled pages, classify forms and links into
authentication flow types (login, register, password reset, OTP/MFA, logout,
OAuth). Pure and deterministic so the heuristics can be unit-tested.
"""

from __future__ import annotations

import re
from enum import StrEnum
from urllib.parse import parse_qs, urlsplit

from pydantic import BaseModel, ConfigDict

from authradar.core.models import Confidence
from authradar.core.parsing import HtmlForm, ParsedPage


class AuthFlowType(StrEnum):
    """Kinds of authentication flow AuthRadar recognises."""

    LOGIN = "login"
    REGISTER = "register"
    PASSWORD_RESET_REQUEST = "password_reset_request"
    PASSWORD_RESET_CONFIRM = "password_reset_confirm"
    CHANGE_PASSWORD = "change_password"
    OTP = "otp"
    MFA = "mfa"
    LOGOUT = "logout"
    OAUTH = "oauth"


class AuthFlow(BaseModel):
    """A detected authentication flow and the evidence behind it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: AuthFlowType
    url: str
    method: str = "get"
    form: HtmlForm | None = None
    confidence: Confidence = Confidence.MEDIUM
    signals: tuple[str, ...] = ()


_IDENTIFIER_FIELDS = frozenset(
    {"username", "user", "login", "email", "e-mail", "userid", "user_id", "account", "j_username"}
)
_EMAIL_FIELDS = frozenset({"email", "e-mail", "mail", "user_email"})
_CONFIRM_PASSWORD_FIELDS = frozenset(
    {"confirm_password", "password_confirm", "password2", "confirmpassword", "repeat_password"}
)
_CHANGE_PASSWORD_FIELDS = frozenset(
    {"old_password", "current_password", "new_password", "oldpassword", "currentpassword"}
)
_TOKEN_FIELDS = frozenset({"token", "reset_token", "code", "key", "t", "verification_token"})
_OTP_FIELDS = frozenset(
    {
        "otp",
        "otp_code",
        "code",
        "totp",
        "mfa_code",
        "one_time_code",
        "verification_code",
        "pin",
        "2fa",
    }
)

_REGISTER_PATH = ("register", "signup", "sign-up", "sign_up", "create-account", "join")
_RESET_PATH = ("reset", "recover", "recovery")
_FORGOT_PATH = ("forgot", "lost-password", "forgot-password")
_LOGIN_PATH = ("login", "signin", "sign-in", "sign_in", "log-in", "auth", "session", "sso")
_CHANGE_PATH = ("change-password", "change_password", "password/change", "update-password")
_OTP_PATH = ("otp", "verify", "verification", "one-time")
_MFA_PATH = ("mfa", "2fa", "two-factor", "twofactor", "authenticator", "totp")
_LOGOUT_PATH = ("logout", "signout", "sign-out", "log-out", "logoff")
_OAUTH_PATH = ("oauth", "authorize", "connect", "openid", "saml")
_OAUTH_QUERY = ("client_id", "response_type", "redirect_uri")

_OTP_VALUE_RE = re.compile(r"^\d{4,8}$")


def _path_of(url: str) -> str:
    return urlsplit(url).path.lower()


def _has_any(path: str, keywords: tuple[str, ...]) -> bool:
    return any(keyword in path for keyword in keywords)


def _password_count(form: HtmlForm) -> int:
    return sum(1 for control in form.inputs if control.type.lower() == "password")


def _has_identifier(form: HtmlForm) -> bool:
    names = set(form.input_names)
    if names & _IDENTIFIER_FIELDS:
        return True
    return any(control.type.lower() in {"email", "text", "tel"} for control in form.inputs)


def _has_otp_field(form: HtmlForm) -> bool:
    if set(form.input_names) & _OTP_FIELDS:
        return True
    return any(
        control.max_length is not None
        and 4 <= control.max_length <= 8
        and control.type.lower() != "password"
        for control in form.inputs
    )


def _confidence(url_agrees: bool, form_agrees: bool) -> Confidence:
    if url_agrees and form_agrees:
        return Confidence.HIGH
    if form_agrees:
        return Confidence.MEDIUM
    return Confidence.LOW


def classify_form(form: HtmlForm) -> AuthFlow | None:  # noqa: PLR0911 - sequential guard returns
    """Classify a single form into an :class:`AuthFlow`, or ``None``."""
    names = set(form.input_names)
    path = _path_of(form.action)
    pwd = _password_count(form)

    def build(
        flow_type: AuthFlowType, url_match: bool, form_match: bool, *signals: str
    ) -> AuthFlow:
        return AuthFlow(
            type=flow_type,
            url=form.action,
            method=form.method,
            form=form,
            confidence=_confidence(url_match, form_match),
            signals=signals,
        )

    if names & _CHANGE_PASSWORD_FIELDS or _has_any(path, _CHANGE_PATH):
        return build(
            AuthFlowType.CHANGE_PASSWORD,
            _has_any(path, _CHANGE_PATH),
            bool(names & _CHANGE_PASSWORD_FIELDS),
            "change-password fields/path",
        )

    if form.has_password and (
        pwd >= 2 or names & _CONFIRM_PASSWORD_FIELDS or _has_any(path, _REGISTER_PATH)
    ):
        return build(
            AuthFlowType.REGISTER,
            _has_any(path, _REGISTER_PATH),
            pwd >= 2 or bool(names & _CONFIRM_PASSWORD_FIELDS),
            "registration signals (confirm password / path)",
        )

    if form.has_password and (names & _TOKEN_FIELDS or _has_any(path, _RESET_PATH)):
        return build(
            AuthFlowType.PASSWORD_RESET_CONFIRM,
            _has_any(path, _RESET_PATH),
            bool(names & _TOKEN_FIELDS),
            "reset-confirm: password + token",
        )

    if (
        not form.has_password
        and (names & _EMAIL_FIELDS)
        and _has_any(path, _RESET_PATH + _FORGOT_PATH)
    ):
        return build(
            AuthFlowType.PASSWORD_RESET_REQUEST,
            True,
            True,
            "reset-request: email on reset/forgot path",
        )

    if _has_otp_field(form) or _has_any(path, _OTP_PATH + _MFA_PATH):
        is_mfa = _has_any(path, _MFA_PATH)
        return build(
            AuthFlowType.MFA if is_mfa else AuthFlowType.OTP,
            _has_any(path, _OTP_PATH + _MFA_PATH),
            _has_otp_field(form),
            "one-time-code field/path",
        )

    if form.has_password and _has_identifier(form):
        return build(
            AuthFlowType.LOGIN,
            _has_any(path, _LOGIN_PATH),
            True,
            "password + identifier field",
        )

    return None


def classify_link(url: str) -> AuthFlow | None:
    """Classify a bare link (logout / OAuth) into an :class:`AuthFlow`."""
    path = _path_of(url)
    query = parse_qs(urlsplit(url).query)
    if _has_any(path, _LOGOUT_PATH):
        return AuthFlow(
            type=AuthFlowType.LOGOUT,
            url=url,
            method="get",
            confidence=Confidence.MEDIUM,
            signals=("logout path",),
        )
    has_oauth_query = any(key in query for key in _OAUTH_QUERY)
    if _has_any(path, _OAUTH_PATH) or has_oauth_query:
        return AuthFlow(
            type=AuthFlowType.OAUTH,
            url=url,
            method="get",
            confidence=Confidence.HIGH if has_oauth_query else Confidence.MEDIUM,
            signals=("oauth path/query parameters",),
        )
    return None


def detect_auth_flows(pages: list[ParsedPage]) -> list[AuthFlow]:
    """Detect all authentication flows across a set of parsed pages.

    De-duplicates by ``(type, url)`` keeping the highest-confidence instance.
    """
    best: dict[tuple[AuthFlowType, str], AuthFlow] = {}

    def consider(flow: AuthFlow | None) -> None:
        if flow is None:
            return
        key = (flow.type, flow.url)
        existing = best.get(key)
        if (
            existing is None
            or _CONFIDENCE_RANK[flow.confidence] > _CONFIDENCE_RANK[existing.confidence]
        ):
            best[key] = flow

    for page in pages:
        for form in page.forms:
            consider(classify_form(form))
        for link in page.links:
            consider(classify_link(link))

    return list(best.values())


_CONFIDENCE_RANK: dict[Confidence, int] = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
}
