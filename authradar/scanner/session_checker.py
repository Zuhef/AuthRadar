"""Session and cookie security analysis.

Passive checks inspect cookie security attributes (Secure / HttpOnly /
SameSite). Active, opt-in checks (requiring credentials and ``active_probes``)
test for session fixation and broken logout invalidation by driving a real
login/logout flow through the request engine.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import ClassVar
from urllib.parse import urljoin

from authradar.core.auth_flow_detector import AuthFlowType
from authradar.core.config import AuthConfig
from authradar.core.exceptions import RequestEngineError
from authradar.core.http import ParsedCookie, SameSite
from authradar.core.models import Category, Confidence, Finding, Severity
from authradar.core.parsing import HtmlForm
from authradar.core.scanner_base import BaseScanner, ScanContext, register_scanner
from authradar.scanner.heuristics import (
    build_login_payload,
    looks_like_auth_cookie,
    looks_like_csrf_cookie,
    looks_like_session_cookie,
)

_LOGGER = logging.getLogger(__name__)
_SCANNER = "session_checker"
_REFS = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie",
)


def extract_session_cookie(cookies: Iterable[ParsedCookie]) -> ParsedCookie | None:
    """Return the most likely session cookie from a set of cookies."""
    auth_fallback: ParsedCookie | None = None
    for cookie in cookies:
        if not cookie.name:
            continue
        if looks_like_session_cookie(cookie.name):
            return cookie
        if auth_fallback is None and looks_like_auth_cookie(cookie.name):
            auth_fallback = cookie
    return auth_fallback


def analyze_cookie_security(
    cookies: Iterable[ParsedCookie],
    *,
    is_https: bool,
) -> list[Finding]:
    """Inspect cookie security attributes; one finding per distinct cookie/issue."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for cookie in cookies:
        key = cookie.name.lower()
        if not cookie.name or key in seen:
            continue
        seen.add(key)

        if cookie.same_site == SameSite.NONE and not cookie.secure:
            findings.append(_cookie_finding(cookie.name, "AR-COOKIE-004"))

        if not looks_like_auth_cookie(cookie.name):
            continue
        if is_https and not cookie.secure:
            findings.append(_cookie_finding(cookie.name, "AR-COOKIE-001"))
        if not cookie.http_only and not looks_like_csrf_cookie(cookie.name):
            findings.append(_cookie_finding(cookie.name, "AR-COOKIE-002"))
        if cookie.same_site is None:
            findings.append(_cookie_finding(cookie.name, "AR-COOKIE-003"))
    return findings


@dataclass(frozen=True, slots=True)
class _CookieCheck:
    title: str
    severity: Severity
    cwe: tuple[int, ...]
    description: str
    remediation: str


_COOKIE_CHECKS: dict[str, _CookieCheck] = {
    "AR-COOKIE-001": _CookieCheck(
        title="Session cookie missing Secure flag",
        severity=Severity.MEDIUM,
        cwe=(614,),
        description=(
            "A session/auth cookie is set without the Secure attribute, so it can be "
            "transmitted over plaintext HTTP and intercepted."
        ),
        remediation="Set the Secure attribute on all session and authentication cookies.",
    ),
    "AR-COOKIE-002": _CookieCheck(
        title="Session cookie missing HttpOnly flag",
        severity=Severity.MEDIUM,
        cwe=(1004,),
        description=(
            "A session/auth cookie is set without HttpOnly, so it is readable by "
            "JavaScript and can be stolen via cross-site scripting."
        ),
        remediation="Set HttpOnly on session and authentication cookies.",
    ),
    "AR-COOKIE-003": _CookieCheck(
        title="Session cookie missing SameSite attribute",
        severity=Severity.LOW,
        cwe=(1275,),
        description=(
            "A session/auth cookie has no SameSite attribute, weakening cross-site "
            "request forgery defences."
        ),
        remediation="Set SameSite=Lax (or Strict) on session and authentication cookies.",
    ),
    "AR-COOKIE-004": _CookieCheck(
        title="Cookie uses SameSite=None without Secure",
        severity=Severity.MEDIUM,
        cwe=(1275,),
        description=(
            "A cookie declares SameSite=None but is not Secure. Browsers reject this "
            "combination, and it exposes the cookie to cross-site transmission over HTTP."
        ),
        remediation="Pair SameSite=None with the Secure attribute, or use SameSite=Lax.",
    ),
}


def _cookie_finding(cookie_name: str, check_id: str) -> Finding:
    spec = _COOKIE_CHECKS[check_id]
    return Finding(
        id=check_id,
        title=spec.title,
        severity=spec.severity,
        confidence=Confidence.HIGH,
        category=Category.SESSION,
        description=spec.description,
        remediation=spec.remediation,
        scanner=_SCANNER,
        location=f"cookie:{cookie_name}",
        evidence=(f"cookie '{cookie_name}'",),
        references=_REFS,
        cwe=spec.cwe,
    )


def analyze_session_fixation(
    pre_session_id: str | None,
    post_session_id: str | None,
    *,
    location: str | None = None,
) -> Finding | None:
    """Flag session fixation: the session identifier is unchanged after login."""
    if pre_session_id and post_session_id and pre_session_id == post_session_id:
        return Finding(
            id="AR-SESSION-001",
            title="Session identifier not rotated after login",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            category=Category.SESSION,
            description=(
                "The session identifier issued before authentication is still valid "
                "afterwards. An attacker who fixes a victim's pre-auth session id can "
                "ride the authenticated session (session fixation)."
            ),
            remediation=(
                "Regenerate the session identifier on every privilege change, especially login."
            ),
            scanner=_SCANNER,
            location=location,
            evidence=("session id identical before and after login",),
            references=_REFS,
            cwe=(384,),
        )
    return None


def analyze_logout_invalidation(
    *,
    authenticated_after_logout: bool,
    location: str | None = None,
) -> Finding | None:
    """Flag broken logout: the session remains usable after logout."""
    if authenticated_after_logout:
        return Finding(
            id="AR-SESSION-002",
            title="Session not invalidated on logout",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            category=Category.SESSION,
            description=(
                "After calling logout, the previously authenticated session token still "
                "grants access to a protected resource. Logout must invalidate the session "
                "server-side, not just clear the client cookie."
            ),
            remediation=(
                "Destroy the server-side session on logout and reject the old token thereafter."
            ),
            scanner=_SCANNER,
            location=location,
            evidence=("protected resource accessible with the post-logout session token",),
            references=_REFS,
            cwe=(613,),
        )
    return None


@dataclass(slots=True)
class _LoginResult:
    pre_id: str | None
    post_id: str | None
    session: dict[str, str] = field(default_factory=dict)


@register_scanner
class SessionCheckerScanner(BaseScanner):
    """Checks cookie flags and (opt-in) session fixation / logout invalidation."""

    id: ClassVar[str] = "session_checker"
    name: ClassVar[str] = "Session & cookie security checker"
    category: ClassVar[Category] = Category.SESSION
    description: ClassVar[str] = "Inspects cookie flags and session lifecycle handling."

    async def scan(self, context: ScanContext) -> list[Finding]:
        findings = analyze_cookie_security(context.set_cookies(), is_https=context.is_https_target)
        findings.extend(await self._stateful_checks(context))
        return findings

    async def _stateful_checks(self, context: ScanContext) -> list[Finding]:
        config = context.config
        auth = config.auth
        if not (config.active_probes and auth and auth.valid):
            return []
        flow = next((f for f in context.flows_of(AuthFlowType.LOGIN) if f.form), None)
        if flow is None or flow.form is None:
            return []

        form = flow.form
        try:
            login = await self._login(context, form, flow.url, auth)
        except RequestEngineError as exc:
            _LOGGER.warning("session fixation probe could not log in: %s", exc)
            return []

        findings: list[Finding] = []
        fixation = analyze_session_fixation(login.pre_id, login.post_id, location=flow.url)
        if fixation is not None:
            findings.append(fixation)

        if auth.logout_path and auth.protected_path and login.session:
            logout_finding = await self._check_logout(
                context, auth.logout_path, auth.protected_path, login.session
            )
            if logout_finding is not None:
                findings.append(logout_finding)
        return findings

    async def _login(
        self,
        context: ScanContext,
        form: HtmlForm,
        action: str,
        auth: AuthConfig,
    ) -> _LoginResult:
        if auth.valid is None:  # pragma: no cover - guarded by caller
            return _LoginResult(pre_id=None, post_id=None)
        engine = context.engine
        login_page = form.source_url or action

        first = await engine.get(login_page)
        pre_cookie = extract_session_cookie(first.cookies)
        jar = {cookie.name: cookie.value for cookie in first.cookies}

        payload = build_login_payload(
            form,
            auth.valid.username,
            auth.valid.password,
            username_field=auth.username_field,
            password_field=auth.password_field,
        )
        second = await engine.post(
            action, data=payload, cookies=jar or None, follow_redirects=False
        )
        post_cookie = extract_session_cookie(second.cookies)
        for cookie in second.cookies:
            jar[cookie.name] = cookie.value

        pre_id = pre_cookie.value if pre_cookie else None
        post_id = post_cookie.value if post_cookie else pre_id
        return _LoginResult(pre_id=pre_id, post_id=post_id, session=jar)

    async def _check_logout(
        self,
        context: ScanContext,
        logout_path: str,
        protected_path: str,
        session: dict[str, str],
    ) -> Finding | None:
        engine = context.engine
        target = context.config.target
        protected_url = urljoin(target, protected_path)
        logout_url = urljoin(target, logout_path)
        try:
            before = await engine.get(protected_url, cookies=session)
            if before.status_code >= 400:
                return None  # session never granted access; nothing to conclude
            await engine.get(logout_url, cookies=session)
            after = await engine.get(protected_url, cookies=session)
        except RequestEngineError as exc:
            _LOGGER.warning("logout invalidation probe failed: %s", exc)
            return None
        return analyze_logout_invalidation(
            authenticated_after_logout=after.status_code < 400,
            location=logout_url,
        )
