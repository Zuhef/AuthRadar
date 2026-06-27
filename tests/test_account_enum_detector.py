"""Tests for authradar.scanner.account_enum_detector pure analysis."""

from __future__ import annotations

from authradar.core.models import Confidence
from authradar.scanner.account_enum_detector import (
    EnumObservation,
    analyze_enumeration,
    classify_message,
)


def test_message_difference_high_confidence() -> None:
    finding = analyze_enumeration(
        EnumObservation(status_code=200, body="incorrect password"),
        EnumObservation(status_code=200, body="user not found"),
    )
    assert finding is not None
    assert finding.id == "AR-ENUM-001"
    assert finding.confidence is Confidence.HIGH


def test_status_difference_high_confidence() -> None:
    finding = analyze_enumeration(
        EnumObservation(status_code=200, body="ok"),
        EnumObservation(status_code=404, body="ok"),
    )
    assert finding is not None
    assert finding.confidence is Confidence.HIGH


def test_identical_responses_clean() -> None:
    obs = EnumObservation(status_code=401, body="invalid credentials")
    assert analyze_enumeration(obs, obs) is None


def test_length_difference_medium_confidence() -> None:
    finding = analyze_enumeration(
        EnumObservation(status_code=200, body="x" * 200),
        EnumObservation(status_code=200, body="y" * 10),
    )
    assert finding is not None
    assert finding.confidence is Confidence.MEDIUM


def test_timing_difference_low_confidence() -> None:
    finding = analyze_enumeration(
        EnumObservation(status_code=200, body="same", elapsed_ms=900.0),
        EnumObservation(status_code=200, body="same", elapsed_ms=100.0),
    )
    assert finding is not None
    assert finding.confidence is Confidence.LOW


def test_classify_message() -> None:
    assert classify_message("User Not Found") == "not_found"
    assert classify_message("Incorrect password") == "wrong_password"
    assert classify_message("Email already registered") == "exists"
    assert classify_message("welcome back") == ""
