"""CSRF protection analysis for authentication flows.

A state-changing authentication form (login, register, password reset/confirm,
change password) submitted with POST is considered CSRF-protected if it carries
an anti-CSRF token field *or* the session cookie uses SameSite=Lax/Strict
(which stops the cookie riding cross-site POSTs).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import ClassVar

from authradar.core.auth_flow_detector import AuthFlowType
from authradar.core.http import ParsedCookie, SameSite
from authradar.core.models import Category, Confidence, Finding, Severity
from authradar.core.parsing import HtmlForm
from authradar.core.scanner_base import BaseScanner, ScanContext, register_scanner
from authradar.scanner.heuristics import looks_like_auth_cookie

_SCANNER = "csrf_auth_analyzer"
_CSRF_FIELD_HINTS = (
    "csrf",
    "xsrf",
    "_csrf",
    "csrf_token",
    "csrfmiddlewaretoken",
    "authenticity_token",
    "__requestverificationtoken",
    "_token",
    "nonce",
)
_STATE_CHANGING = (
    AuthFlowType.LOGIN,
    AuthFlowType.REGISTER,
    AuthFlowType.PASSWORD_RESET_REQUEST,
    AuthFlowType.PASSWORD_RESET_CONFIRM,
    AuthFlowType.CHANGE_PASSWORD,
)
_REFS = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
)


def has_csrf_field(form: HtmlForm) -> bool:
    """Whether the form carries a plausible anti-CSRF token field."""
    for control in form.inputs:
        name = control.name.lower()
        if any(hint in name for hint in _CSRF_FIELD_HINTS):
            return True
    return False


def cookies_provide_samesite_protection(cookies: Iterable[ParsedCookie]) -> bool:
    """Whether any session/auth cookie uses SameSite=Lax or Strict."""
    return any(
        looks_like_auth_cookie(cookie.name) and cookie.same_site in (SameSite.LAX, SameSite.STRICT)
        for cookie in cookies
    )


def analyze_csrf_protection(
    form: HtmlForm,
    *,
    flow_type: AuthFlowType,
    samesite_protected: bool,
) -> Finding | None:
    """Return a CSRF finding if a state-changing POST form is unprotected."""
    if form.method != "post":
        return None
    if has_csrf_field(form) or samesite_protected:
        return None
    return Finding(
        id="AR-CSRF-001",
        title="Authentication form lacks CSRF protection",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category=Category.CSRF,
        description=(
            f"The {flow_type.value} form is submitted with POST but has no anti-CSRF "
            "token, and no session cookie uses SameSite=Lax/Strict. An attacker page can "
            "forge this request using the victim's session."
        ),
        remediation=(
            "Add a per-session anti-CSRF token to state-changing forms and/or set "
            "SameSite=Lax (or Strict) on session cookies."
        ),
        scanner=_SCANNER,
        location=form.action,
        evidence=(f"{flow_type.value} POST form without CSRF token or SameSite cookie",),
        references=_REFS,
        cwe=(352,),
    )


@register_scanner
class CsrfAuthAnalyzerScanner(BaseScanner):
    """Detects authentication forms without CSRF protection."""

    id: ClassVar[str] = "csrf_auth_analyzer"
    name: ClassVar[str] = "CSRF authentication analyzer"
    category: ClassVar[Category] = Category.CSRF
    description: ClassVar[str] = "Checks auth forms for anti-CSRF protection."

    async def scan(self, context: ScanContext) -> list[Finding]:
        samesite_protected = cookies_provide_samesite_protection(context.set_cookies())
        findings: list[Finding] = []
        for flow in context.flows_of(*_STATE_CHANGING):
            if flow.form is None:
                continue
            finding = analyze_csrf_protection(
                flow.form,
                flow_type=flow.type,
                samesite_protected=samesite_protected,
            )
            if finding is not None:
                findings.append(finding)
        return findings
