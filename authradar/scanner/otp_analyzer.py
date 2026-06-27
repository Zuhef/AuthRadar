"""One-time-password (OTP) strength and brute-force analysis.

Passive analysis inspects an OTP form for a too-short code. The opt-in active
probe submits a bounded number of wrong codes to detect missing rate limiting
on OTP verification (which enables OTP brute force).
"""

from __future__ import annotations

import logging
from typing import ClassVar

from authradar.core.auth_flow_detector import AuthFlow, AuthFlowType
from authradar.core.config import ScanConfig
from authradar.core.exceptions import RequestEngineError
from authradar.core.models import Category, Confidence, Finding, Severity
from authradar.core.parsing import FormInput, HtmlForm
from authradar.core.scanner_base import BaseScanner, ScanContext, register_scanner
from authradar.scanner.heuristics import indicates_throttling
from authradar.scanner.rate_limit_tester import ProbeResponse

_LOGGER = logging.getLogger(__name__)
_SCANNER = "otp_analyzer"
_MIN_OTP_LENGTH = 6
_MIN_ATTEMPTS = 5
_OTP_FIELD_HINTS = (
    "otp",
    "code",
    "totp",
    "mfa_code",
    "one_time",
    "onetime",
    "verification_code",
    "passcode",
    "pin",
    "2fa",
)
_NON_VALUE_INPUTS = frozenset({"submit", "button", "image", "reset"})
_REFS = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html",
)


def find_otp_input(form: HtmlForm) -> FormInput | None:
    """Locate the OTP/verification-code control in a form."""
    for control in form.inputs:
        name = control.name.lower()
        if any(hint in name for hint in _OTP_FIELD_HINTS):
            return control
    for control in form.inputs:
        if (
            control.type.lower() in {"number", "tel", "text"}
            and control.max_length is not None
            and 4 <= control.max_length <= 8
        ):
            return control
    return None


def analyze_otp_form(form: HtmlForm) -> list[Finding]:
    """Flag a too-short OTP based on the input's max length."""
    otp = find_otp_input(form)
    if otp is None or otp.max_length is None or otp.max_length >= _MIN_OTP_LENGTH:
        return []
    return [
        Finding(
            id="AR-OTP-001",
            title="One-time password is too short",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            category=Category.OTP,
            description=(
                f"The OTP field accepts only {otp.max_length} characters. Short codes have a "
                "small keyspace and are feasible to brute-force, especially without strict "
                "rate limiting and short expiry."
            ),
            remediation=(
                "Use at least 6-digit OTPs, expire them quickly, and rate-limit verification."
            ),
            scanner=_SCANNER,
            location=form.action,
            evidence=(f"OTP field '{otp.name}' maxlength={otp.max_length}",),
            references=_REFS,
            cwe=(307,),
        )
    ]


def analyze_otp_rate_limiting(
    probes: list[ProbeResponse],
    *,
    min_attempts: int = _MIN_ATTEMPTS,
) -> Finding | None:
    """Flag missing rate limiting on OTP verification."""
    attempts = len(probes)
    if attempts < min_attempts:
        return None
    defended = any(
        indicates_throttling(p.status_code, retry_after=p.retry_after, body=p.body) for p in probes
    )
    if defended:
        return None
    return Finding(
        id="AR-OTP-002",
        title="OTP verification lacks rate limiting",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH if attempts >= 10 else Confidence.MEDIUM,
        category=Category.OTP,
        description=(
            f"{attempts} consecutive wrong OTP submissions produced no throttling or "
            "lockout. Combined with a small OTP keyspace this allows OTP brute force, "
            "bypassing the second factor."
        ),
        remediation=(
            "Limit OTP attempts per code/session, invalidate the code after a few "
            "failures, and expire codes quickly."
        ),
        scanner=_SCANNER,
        location=None,
        evidence=(f"{attempts} wrong OTPs, no throttling observed",),
        references=_REFS,
        cwe=(307,),
    )


def _build_otp_payload(form: HtmlForm, otp_field: str, code: str) -> dict[str, str]:
    data: dict[str, str] = {
        control.name: control.value
        for control in form.inputs
        if control.type.lower() not in _NON_VALUE_INPUTS
    }
    data[otp_field] = code
    return data


@register_scanner
class OtpAnalyzerScanner(BaseScanner):
    """Analyses OTP forms and (opt-in) probes for OTP brute-force exposure."""

    id: ClassVar[str] = "otp_analyzer"
    name: ClassVar[str] = "OTP analyzer"
    category: ClassVar[Category] = Category.OTP
    description: ClassVar[str] = "Checks OTP length and brute-force protection."

    async def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        otp_flows = context.flows_of(AuthFlowType.OTP, AuthFlowType.MFA)
        for flow in otp_flows:
            if flow.form is not None:
                findings.extend(analyze_otp_form(flow.form))

        if context.config.active_probes:
            probe_flow = next((f for f in otp_flows if f.form), None)
            if probe_flow is not None:
                findings.extend(await self._probe(context, probe_flow, context.config))
        return findings

    async def _probe(
        self, context: ScanContext, flow: AuthFlow, config: ScanConfig
    ) -> list[Finding]:
        form = flow.form
        if form is None:  # pragma: no cover - guarded by caller
            return []
        otp = find_otp_input(form)
        if otp is None:
            return []
        engine = context.engine
        probes: list[ProbeResponse] = []
        for attempt in range(config.probe_attempts):
            payload = _build_otp_payload(form, otp.name, f"{attempt:06d}")
            try:
                response = await engine.post(flow.url, data=payload, follow_redirects=False)
            except RequestEngineError as exc:
                _LOGGER.warning("OTP probe aborted after %d attempts: %s", attempt, exc)
                break
            probes.append(
                ProbeResponse(
                    status_code=response.status_code,
                    retry_after=response.header("retry-after") is not None,
                    body=response.body[:2000],
                    elapsed_ms=response.elapsed_ms,
                )
            )
        finding = analyze_otp_rate_limiting(probes)
        if finding is None:
            return []
        return [finding.model_copy(update={"location": flow.url})]
