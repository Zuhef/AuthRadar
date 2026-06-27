"""Login rate-limiting / brute-force exposure testing.

The pure analyzer decides, from a series of failed-login probe responses,
whether the endpoint enforces rate limiting. The active probe (gated behind
``active_probes``) sends a bounded number of failed logins using a deliberately
*invalid* username, so it exercises endpoint/IP rate limiting without risking
lockout of a real account.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import ClassVar

from authradar.core.auth_flow_detector import AuthFlow, AuthFlowType
from authradar.core.config import ScanConfig
from authradar.core.exceptions import RequestEngineError
from authradar.core.models import Category, Confidence, Finding, Severity
from authradar.core.scanner_base import BaseScanner, ScanContext, register_scanner
from authradar.scanner.heuristics import build_login_payload, indicates_throttling

_LOGGER = logging.getLogger(__name__)
_SCANNER = "rate_limit_tester"
_MIN_ATTEMPTS = 5
_REFS = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#account-lockout",
    "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
)


@dataclass(frozen=True, slots=True)
class ProbeResponse:
    """A single failed-login probe observation."""

    status_code: int
    retry_after: bool = False
    body: str = ""
    elapsed_ms: float = 0.0


def _is_defended(probe: ProbeResponse) -> bool:
    return indicates_throttling(probe.status_code, retry_after=probe.retry_after, body=probe.body)


def analyze_rate_limiting(
    probes: list[ProbeResponse],
    *,
    min_attempts: int = _MIN_ATTEMPTS,
) -> Finding | None:
    """Flag missing rate limiting if no defence appears across enough attempts."""
    attempts = len(probes)
    if attempts < min_attempts:
        return None
    if any(_is_defended(probe) for probe in probes):
        return None
    confidence = Confidence.HIGH if attempts >= 10 else Confidence.MEDIUM
    return Finding(
        id="AR-RATE-001",
        title="Login endpoint lacks rate limiting",
        severity=Severity.HIGH,
        confidence=confidence,
        category=Category.RATE_LIMITING,
        description=(
            f"{attempts} consecutive failed login attempts produced no rate limiting, "
            "lockout, CAPTCHA or 429 response. This enables credential brute-force and "
            "password-spraying attacks."
        ),
        remediation=(
            "Enforce progressive throttling and temporary lockout per account and per "
            "source IP, return HTTP 429 with Retry-After, and consider CAPTCHA after "
            "repeated failures."
        ),
        scanner=_SCANNER,
        location=None,
        evidence=(f"{attempts} failed logins, no throttling observed",),
        references=_REFS,
        cwe=(307, 799),
    )


@register_scanner
class RateLimitTesterScanner(BaseScanner):
    """Actively probes the login endpoint for missing rate limiting (opt-in)."""

    id: ClassVar[str] = "rate_limit_tester"
    name: ClassVar[str] = "Login rate-limit tester"
    category: ClassVar[Category] = Category.RATE_LIMITING
    description: ClassVar[str] = "Probes login for brute-force protection (active)."

    async def scan(self, context: ScanContext) -> list[Finding]:
        config = context.config
        if not config.active_probes:
            return []
        flow = next((f for f in context.flows_of(AuthFlowType.LOGIN) if f.form), None)
        if flow is None or flow.form is None:
            return []

        probes = await self._probe(context, flow, config)
        finding = analyze_rate_limiting(probes)
        if finding is None:
            return []
        return [finding.model_copy(update={"location": flow.url})]

    async def _probe(
        self, context: ScanContext, flow: AuthFlow, config: ScanConfig
    ) -> list[ProbeResponse]:
        form = flow.form
        if form is None:  # pragma: no cover - guarded by caller
            return []
        engine = context.engine
        auth = config.auth
        username = auth.invalid_username if auth else "authradar-unknown-user"
        username_field = auth.username_field if auth else "username"
        password_field = auth.password_field if auth else "password"

        probes: list[ProbeResponse] = []
        for attempt in range(config.probe_attempts):
            payload = build_login_payload(
                form,
                username,
                f"AuthRadar-invalid-{attempt}",
                username_field=username_field,
                password_field=password_field,
            )
            try:
                response = await engine.post(flow.url, data=payload, follow_redirects=False)
            except RequestEngineError as exc:
                _LOGGER.warning("rate-limit probe aborted after %d attempts: %s", attempt, exc)
                break
            probes.append(
                ProbeResponse(
                    status_code=response.status_code,
                    retry_after=response.header("retry-after") is not None,
                    body=response.body[:2000],
                    elapsed_ms=response.elapsed_ms,
                )
            )
        return probes
