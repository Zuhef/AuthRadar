"""Multi-factor authentication (MFA) validation.

Detects two classes of MFA weakness:

* **MFA bypass** - a protected resource is reachable after only the first
  factor, before the second factor is completed.
* **Broken step validation** - the MFA verification step accepts an empty or
  invalid code and still grants access.

Both require credentials, a protected path, and a detected MFA/OTP step, and
run only when ``active_probes`` is enabled. The decision logic is pure and
unit-tested.
"""

from __future__ import annotations

import logging
from typing import ClassVar
from urllib.parse import urljoin

from authradar.core.auth_flow_detector import AuthFlow, AuthFlowType
from authradar.core.config import AuthConfig
from authradar.core.exceptions import RequestEngineError
from authradar.core.models import Category, Confidence, Finding, Severity
from authradar.core.parsing import HtmlForm
from authradar.core.scanner_base import BaseScanner, ScanContext, register_scanner
from authradar.scanner.heuristics import build_login_payload
from authradar.scanner.otp_analyzer import find_otp_input

_LOGGER = logging.getLogger(__name__)
_SCANNER = "mfa_validator"
_NON_VALUE_INPUTS = frozenset({"submit", "button", "image", "reset"})
_REFS = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html",
)


def analyze_mfa_bypass(
    *,
    mfa_expected: bool,
    protected_accessible: bool,
    location: str | None = None,
) -> Finding | None:
    """Flag MFA bypass: protected resource reachable before the second factor."""
    if mfa_expected and protected_accessible:
        return Finding(
            id="AR-MFA-001",
            title="MFA can be bypassed after the first factor",
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,
            category=Category.MFA,
            description=(
                "The application enforces a second factor, yet a protected resource was "
                "accessible using only the first-factor (password) session, before the MFA "
                "step was completed. This defeats the purpose of MFA."
            ),
            remediation=(
                "Mark the session as 'MFA pending' until the second factor succeeds and "
                "deny access to all protected resources until then."
            ),
            scanner=_SCANNER,
            location=location,
            evidence=("protected resource reachable with first-factor-only session",),
            references=_REFS,
            cwe=(287, 306),
        )
    return None


def analyze_mfa_step_validation(
    *,
    accepts_invalid_code: bool,
    location: str | None = None,
) -> Finding | None:
    """Flag broken MFA step validation: an empty/invalid code is accepted."""
    if accepts_invalid_code:
        return Finding(
            id="AR-MFA-002",
            title="MFA step accepts an empty or invalid code",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            category=Category.MFA,
            description=(
                "Submitting an empty or clearly invalid second-factor code still granted "
                "access to a protected resource, indicating the MFA verification step is "
                "not enforced server-side."
            ),
            remediation=(
                "Strictly validate the second-factor code server-side before granting access."
            ),
            scanner=_SCANNER,
            location=location,
            evidence=("protected resource reachable after submitting an invalid MFA code",),
            references=_REFS,
            cwe=(287,),
        )
    return None


@register_scanner
class MfaValidatorScanner(BaseScanner):
    """Probes for MFA bypass and broken step validation (opt-in)."""

    id: ClassVar[str] = "mfa_validator"
    name: ClassVar[str] = "MFA validator"
    category: ClassVar[Category] = Category.MFA
    description: ClassVar[str] = "Checks for MFA bypass and weak step validation."

    async def scan(self, context: ScanContext) -> list[Finding]:
        config = context.config
        auth = config.auth
        if not (config.active_probes and auth and auth.valid and auth.protected_path):
            return []
        mfa_flows = context.flows_of(AuthFlowType.OTP, AuthFlowType.MFA)
        if not mfa_flows:
            return []
        login_flow = next((f for f in context.flows_of(AuthFlowType.LOGIN) if f.form), None)
        if login_flow is None or login_flow.form is None:
            return []

        try:
            return await self._run(context, login_flow, login_flow.form, mfa_flows, auth)
        except RequestEngineError as exc:
            _LOGGER.warning("MFA probe failed: %s", exc)
            return []

    async def _run(
        self,
        context: ScanContext,
        login_flow: AuthFlow,
        login_form: HtmlForm,
        mfa_flows: list[AuthFlow],
        auth: AuthConfig,
    ) -> list[Finding]:
        if auth.valid is None or auth.protected_path is None:  # pragma: no cover - guarded
            return []
        engine = context.engine
        protected_url = urljoin(context.config.target, auth.protected_path)

        session = await self._first_factor(context, login_flow.url, login_form, auth)
        before = await engine.get(protected_url, cookies=session or None)
        accessible = before.status_code < 400

        findings: list[Finding] = []
        bypass = analyze_mfa_bypass(
            mfa_expected=True, protected_accessible=accessible, location=protected_url
        )
        if bypass is not None:
            findings.append(bypass)
            return findings  # already bypassed; step-validation check is moot

        mfa_flow = next((f for f in mfa_flows if f.form), None)
        if mfa_flow is not None and mfa_flow.form is not None:
            accepts_invalid = await self._submit_invalid_code(
                context, mfa_flow.url, mfa_flow.form, session, protected_url
            )
            step = analyze_mfa_step_validation(
                accepts_invalid_code=accepts_invalid, location=mfa_flow.url
            )
            if step is not None:
                findings.append(step)
        return findings

    async def _first_factor(
        self, context: ScanContext, action: str, form: HtmlForm, auth: AuthConfig
    ) -> dict[str, str]:
        if auth.valid is None:  # pragma: no cover - guarded by caller
            return {}
        engine = context.engine
        first = await engine.get(form.source_url or action)
        jar = {cookie.name: cookie.value for cookie in first.cookies}
        payload = build_login_payload(
            form,
            auth.valid.username,
            auth.valid.password,
            username_field=auth.username_field,
            password_field=auth.password_field,
        )
        response = await engine.post(
            action, data=payload, cookies=jar or None, follow_redirects=False
        )
        for cookie in response.cookies:
            jar[cookie.name] = cookie.value
        return jar

    async def _submit_invalid_code(
        self,
        context: ScanContext,
        action: str,
        form: HtmlForm,
        session: dict[str, str],
        protected_url: str,
    ) -> bool:
        engine = context.engine
        otp = find_otp_input(form)
        payload: dict[str, str] = {
            control.name: control.value
            for control in form.inputs
            if control.type.lower() not in _NON_VALUE_INPUTS
        }
        if otp is not None:
            payload[otp.name] = ""  # deliberately invalid (empty) code
        await engine.post(action, data=payload, cookies=session or None, follow_redirects=False)
        after = await engine.get(protected_url, cookies=session or None)
        return after.status_code < 400
