"""Tests for authradar.scanner.otp_analyzer pure functions."""

from __future__ import annotations

from authradar.core.parsing import FormInput, HtmlForm
from authradar.scanner.otp_analyzer import (
    analyze_otp_form,
    analyze_otp_rate_limiting,
    find_otp_input,
)
from authradar.scanner.rate_limit_tester import ProbeResponse


def _otp_form(max_length: int) -> HtmlForm:
    return HtmlForm(
        action="http://t/otp",
        method="post",
        inputs=(FormInput(name="otp", type="text", max_length=max_length),),
        source_url="http://t/otp",
    )


def test_short_otp_flagged() -> None:
    ids = {f.id for f in analyze_otp_form(_otp_form(4))}
    assert "AR-OTP-001" in ids


def test_six_digit_otp_clean() -> None:
    assert analyze_otp_form(_otp_form(6)) == []


def test_find_otp_input() -> None:
    found = find_otp_input(_otp_form(6))
    assert found is not None
    assert found.name == "otp"


def test_otp_rate_limit_missing() -> None:
    finding = analyze_otp_rate_limiting([ProbeResponse(status_code=200) for _ in range(8)])
    assert finding is not None
    assert finding.id == "AR-OTP-002"


def test_otp_rate_limited_clean() -> None:
    probes = [ProbeResponse(status_code=200) for _ in range(7)]
    probes.append(ProbeResponse(status_code=429))
    assert analyze_otp_rate_limiting(probes) is None


def test_too_few_attempts_inconclusive() -> None:
    assert analyze_otp_rate_limiting([ProbeResponse(status_code=200)] * 3) is None
