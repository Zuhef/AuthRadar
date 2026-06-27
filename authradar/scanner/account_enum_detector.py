"""Account / username enumeration detection.

Compares the application's response to a known-valid identifier versus an
invalid one. Differences in status code, response length, wording, or timing
let an attacker learn which accounts exist. The active probe is opt-in and
requires the operator to supply a valid identifier they own; the comparison
logic is a pure, tested function.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import ClassVar

from authradar.core.auth_flow_detector import AuthFlow, AuthFlowType
from authradar.core.config import AuthConfig
from authradar.core.exceptions import RequestEngineError
from authradar.core.models import Category, Confidence, Finding, Severity
from authradar.core.parsing import HtmlForm
from authradar.core.scanner_base import BaseScanner, ScanContext, register_scanner

_LOGGER = logging.getLogger(__name__)
_SCANNER = "account_enum_detector"
_NON_VALUE_INPUTS = frozenset({"submit", "button", "image", "reset"})
_IDENTIFIER_TYPES = frozenset({"email", "text", "tel"})
_LENGTH_RATIO = 0.30
_LENGTH_ABS = 40
_TIMING_RATIO = 3.0
_TIMING_ABS_MS = 200.0
_REFS = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#authentication-and-error-messages",
    "https://owasp.org/www-community/attacks/Account_enumeration",
)

_NOT_FOUND_PHRASES = (
    "not found",
    "no account",
    "does not exist",
    "doesn't exist",
    "not registered",
    "unknown user",
    "no user",
    "no such user",
    "email not found",
)
_WRONG_PASSWORD_PHRASES = (
    "incorrect password",
    "wrong password",
    "invalid password",
    "password is incorrect",
    "password incorrect",
)
_EXISTS_PHRASES = (
    "already exists",
    "already registered",
    "already taken",
    "is taken",
    "already in use",
)


@dataclass(frozen=True, slots=True)
class EnumObservation:
    """A response observation for one identifier probe."""

    status_code: int
    body: str = ""
    elapsed_ms: float = 0.0


def classify_message(body: str) -> str:
    """Tag a response body as not_found / wrong_password / exists / empty."""
    lowered = body.lower()
    if any(phrase in lowered for phrase in _NOT_FOUND_PHRASES):
        return "not_found"
    if any(phrase in lowered for phrase in _WRONG_PASSWORD_PHRASES):
        return "wrong_password"
    if any(phrase in lowered for phrase in _EXISTS_PHRASES):
        return "exists"
    return ""


def analyze_enumeration(
    valid: EnumObservation,
    invalid: EnumObservation,
    *,
    location: str | None = None,
) -> Finding | None:
    """Detect account enumeration from a valid vs invalid identifier response."""
    signals: list[str] = []

    status_differs = valid.status_code != invalid.status_code
    if status_differs:
        signals.append(f"status {valid.status_code} vs {invalid.status_code}")

    len_valid, len_invalid = len(valid.body), len(invalid.body)
    longest = max(len_valid, len_invalid)
    length_differs = (
        longest > 0
        and abs(len_valid - len_invalid) / longest > _LENGTH_RATIO
        and abs(len_valid - len_invalid) > _LENGTH_ABS
    )
    if length_differs:
        signals.append(f"body length {len_valid} vs {len_invalid}")

    tag_valid, tag_invalid = classify_message(valid.body), classify_message(invalid.body)
    message_differs = tag_valid != tag_invalid and bool(tag_valid or tag_invalid)
    if message_differs:
        signals.append(f"messages '{tag_valid}' vs '{tag_invalid}'")

    timing_differs = False
    if valid.elapsed_ms > 0 and invalid.elapsed_ms > 0:
        slower = max(valid.elapsed_ms, invalid.elapsed_ms)
        faster = min(valid.elapsed_ms, invalid.elapsed_ms)
        timing_differs = slower / faster > _TIMING_RATIO and slower - faster > _TIMING_ABS_MS
        if timing_differs:
            signals.append(f"timing {valid.elapsed_ms:.0f}ms vs {invalid.elapsed_ms:.0f}ms")

    if not signals:
        return None

    if status_differs or message_differs:
        confidence = Confidence.HIGH
    elif length_differs:
        confidence = Confidence.MEDIUM
    else:
        confidence = Confidence.LOW

    return Finding(
        id="AR-ENUM-001",
        title="Account enumeration via response differences",
        severity=Severity.MEDIUM,
        confidence=confidence,
        category=Category.ACCOUNT_ENUMERATION,
        description=(
            "The application responds differently to a valid identifier than to an invalid "
            "one, allowing an attacker to enumerate which accounts exist and target them "
            "for password spraying or phishing."
        ),
        remediation=(
            "Return identical responses (status, body and timing) regardless of whether the "
            "account exists; use generic messages such as 'if the account exists, an email "
            "was sent'."
        ),
        scanner=_SCANNER,
        location=location,
        evidence=tuple(signals),
        references=_REFS,
        cwe=(204,),
    )


def _build_payload(form: HtmlForm, identifier: str, *, username_field: str) -> dict[str, str]:
    data: dict[str, str] = {
        control.name: control.value
        for control in form.inputs
        if control.type.lower() not in _NON_VALUE_INPUTS
    }
    field = username_field if form.get_input(username_field) else None
    if field is None:
        candidate = next((c for c in form.inputs if c.type.lower() in _IDENTIFIER_TYPES), None)
        field = candidate.name if candidate else username_field
    data[field] = identifier
    password_input = form.input_by_type("password")
    if password_input is not None:
        data[password_input.name] = "AuthRadar-invalid-pw"
    return data


@register_scanner
class AccountEnumDetectorScanner(BaseScanner):
    """Detects account enumeration on login/forgot-password flows (opt-in)."""

    id: ClassVar[str] = "account_enum_detector"
    name: ClassVar[str] = "Account enumeration detector"
    category: ClassVar[Category] = Category.ACCOUNT_ENUMERATION
    description: ClassVar[str] = "Compares valid vs invalid identifier responses."

    async def scan(self, context: ScanContext) -> list[Finding]:
        config = context.config
        auth = config.auth
        if not (config.active_probes and auth and auth.valid):
            return []
        flow = self._pick_flow(context)
        if flow is None or flow.form is None:
            return []

        try:
            valid_obs = await self._observe(context, flow, flow.form, auth.valid.username, auth)
            invalid_obs = await self._observe(context, flow, flow.form, auth.invalid_username, auth)
        except RequestEngineError as exc:
            _LOGGER.warning("account enumeration probe failed: %s", exc)
            return []

        finding = analyze_enumeration(valid_obs, invalid_obs, location=flow.url)
        return [finding] if finding is not None else []

    @staticmethod
    def _pick_flow(context: ScanContext) -> AuthFlow | None:
        for flow in context.flows_of(AuthFlowType.PASSWORD_RESET_REQUEST):
            if flow.form is not None:
                return flow
        return next((f for f in context.flows_of(AuthFlowType.LOGIN) if f.form), None)

    async def _observe(
        self,
        context: ScanContext,
        flow: AuthFlow,
        form: HtmlForm,
        identifier: str,
        auth: AuthConfig,
    ) -> EnumObservation:
        payload = _build_payload(form, identifier, username_field=auth.username_field)
        response = await context.engine.post(flow.url, data=payload, follow_redirects=False)
        return EnumObservation(
            status_code=response.status_code,
            body=response.body[:4000],
            elapsed_ms=response.elapsed_ms,
        )
