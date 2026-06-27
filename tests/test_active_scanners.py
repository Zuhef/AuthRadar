"""Isolated integration tests for active scanners against ASGI apps.

Each test drives a single scanner against an in-process app with its own
client (and thus its own cookie jar) so behaviour is deterministic.
"""

from __future__ import annotations

from fastapi import FastAPI

from authradar.core.auth_flow_detector import AuthFlow, AuthFlowType
from authradar.core.config import AuthConfig, Credentials, ScanConfig
from authradar.core.parsing import FormInput, HtmlForm
from authradar.core.scanner_base import BaseScanner, ScanContext
from authradar.scanner.account_enum_detector import AccountEnumDetectorScanner
from authradar.scanner.mfa_validator import MfaValidatorScanner
from authradar.scanner.rate_limit_tester import RateLimitTesterScanner
from authradar.scanner.session_checker import SessionCheckerScanner
from tests.apps import VALID_PASSWORD, VALID_USER, build_secure_app, build_vulnerable_app
from tests.helpers import engine_for, login_flow, make_config


def _auth(*, protected_path: str | None = None, logout_path: str | None = None) -> AuthConfig:
    return AuthConfig(
        valid=Credentials(username=VALID_USER, password=VALID_PASSWORD),
        protected_path=protected_path,
        logout_path=logout_path,
    )


def _context(app: FastAPI, config: ScanConfig, *flows: AuthFlow) -> ScanContext:
    return ScanContext(config=config, engine=engine_for(app, config), auth_flows=list(flows))


async def _run(scanner: BaseScanner, context: ScanContext) -> set[str]:
    async with context.engine:
        findings = await scanner.scan(context)
    return {finding.id for finding in findings}


async def test_session_fixation_and_logout_detected() -> None:
    config = make_config(
        active_probes=True,
        auth=_auth(protected_path="/dashboard", logout_path="/logout"),
    )
    ids = await _run(
        SessionCheckerScanner(), _context(build_vulnerable_app(), config, login_flow())
    )
    assert "AR-SESSION-001" in ids
    assert "AR-SESSION-002" in ids


async def test_session_secure_app_clean() -> None:
    config = make_config(
        active_probes=True,
        auth=_auth(protected_path="/dashboard", logout_path="/logout"),
    )
    ids = await _run(SessionCheckerScanner(), _context(build_secure_app(), config, login_flow()))
    assert "AR-SESSION-001" not in ids
    assert "AR-SESSION-002" not in ids


async def test_rate_limit_detected_on_vulnerable() -> None:
    config = make_config(active_probes=True, probe_attempts=8, auth=_auth())
    ids = await _run(
        RateLimitTesterScanner(), _context(build_vulnerable_app(), config, login_flow())
    )
    assert "AR-RATE-001" in ids


async def test_rate_limit_clean_on_secure() -> None:
    config = make_config(active_probes=True, probe_attempts=8, auth=_auth())
    ids = await _run(RateLimitTesterScanner(), _context(build_secure_app(), config, login_flow()))
    assert "AR-RATE-001" not in ids


async def test_account_enumeration_detected() -> None:
    config = make_config(active_probes=True, auth=_auth())
    ids = await _run(
        AccountEnumDetectorScanner(), _context(build_vulnerable_app(), config, login_flow())
    )
    assert "AR-ENUM-001" in ids


async def test_account_enumeration_clean_on_secure() -> None:
    config = make_config(active_probes=True, auth=_auth())
    ids = await _run(
        AccountEnumDetectorScanner(), _context(build_secure_app(), config, login_flow())
    )
    assert "AR-ENUM-001" not in ids


def _otp_flow() -> AuthFlow:
    form = HtmlForm(
        action="http://testserver/verify-otp",
        method="post",
        inputs=(FormInput(name="otp", type="text", max_length=6),),
        source_url="http://testserver/verify-otp",
    )
    return AuthFlow(type=AuthFlowType.OTP, url=form.action, method="post", form=form)


async def test_mfa_bypass_detected() -> None:
    config = make_config(active_probes=True, auth=_auth(protected_path="/dashboard"))
    ids = await _run(
        MfaValidatorScanner(),
        _context(build_vulnerable_app(), config, login_flow(), _otp_flow()),
    )
    assert "AR-MFA-001" in ids
