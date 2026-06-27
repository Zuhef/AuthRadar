"""Tests for authradar.scanner.mfa_validator pure analysis."""

from __future__ import annotations

from authradar.scanner.mfa_validator import analyze_mfa_bypass, analyze_mfa_step_validation


def test_bypass_detected() -> None:
    finding = analyze_mfa_bypass(mfa_expected=True, protected_accessible=True)
    assert finding is not None
    assert finding.id == "AR-MFA-001"


def test_no_bypass_when_protected() -> None:
    assert analyze_mfa_bypass(mfa_expected=True, protected_accessible=False) is None


def test_no_bypass_when_no_mfa() -> None:
    assert analyze_mfa_bypass(mfa_expected=False, protected_accessible=True) is None


def test_step_validation_accepts_invalid() -> None:
    finding = analyze_mfa_step_validation(accepts_invalid_code=True)
    assert finding is not None
    assert finding.id == "AR-MFA-002"


def test_step_validation_clean() -> None:
    assert analyze_mfa_step_validation(accepts_invalid_code=False) is None
