"""Login form detection and transport-security checks.

Flags login forms that submit credentials over cleartext HTTP or via the GET
method (which leaks credentials into URLs, logs and history).
"""

from __future__ import annotations

from typing import ClassVar
from urllib.parse import urlsplit

from authradar.core.auth_flow_detector import AuthFlowType
from authradar.core.models import Category, Confidence, Finding, Severity
from authradar.core.parsing import HtmlForm
from authradar.core.scanner_base import BaseScanner, ScanContext, register_scanner

_SCANNER = "login_detector"
_REFS = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
)


def analyze_login_security(form: HtmlForm) -> list[Finding]:
    """Inspect a login form for transport and method weaknesses."""
    findings: list[Finding] = []
    action_scheme = urlsplit(form.action).scheme
    page_scheme = urlsplit(form.source_url).scheme if form.source_url else action_scheme

    if action_scheme == "http" or page_scheme == "http":
        findings.append(
            Finding(
                id="AR-LOGIN-001",
                title="Login form transmitted over cleartext HTTP",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.TRANSPORT,
                description=(
                    "The login form is served or submitted over plain HTTP. Credentials "
                    "can be read or modified by anyone on the network path, and the page "
                    "itself can be tampered with to alter where credentials are sent."
                ),
                remediation=(
                    "Serve and submit all authentication pages exclusively over HTTPS, "
                    "and enable HSTS."
                ),
                scanner=_SCANNER,
                location=form.action,
                evidence=(f"action={form.action!r}", f"page={form.source_url!r}"),
                references=_REFS,
                cwe=(319,),
            )
        )

    if form.method == "get":
        findings.append(
            Finding(
                id="AR-LOGIN-002",
                title="Login form uses the GET method",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.LOGIN,
                description=(
                    "The login form submits via GET, placing the username and password in "
                    "the URL. They will be stored in browser history, server access logs "
                    "and proxy logs, and leak via the Referer header."
                ),
                remediation="Submit credentials with POST (and over HTTPS).",
                scanner=_SCANNER,
                location=form.action,
                evidence=(f"method=GET action={form.action!r}",),
                references=_REFS,
                cwe=(598,),
            )
        )
    return findings


@register_scanner
class LoginDetectorScanner(BaseScanner):
    """Analyses detected login forms for transport and method weaknesses."""

    id: ClassVar[str] = "login_detector"
    name: ClassVar[str] = "Login transport detector"
    category: ClassVar[Category] = Category.LOGIN
    description: ClassVar[str] = "Detects cleartext or GET-based login forms."

    async def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for flow in context.flows_of(AuthFlowType.LOGIN):
            if flow.form is not None:
                findings.extend(analyze_login_security(flow.form))
        return findings
