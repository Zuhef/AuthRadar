"""Tests for authradar.scanner.rate_limit_tester pure analysis."""

from __future__ import annotations

from authradar.core.models import Confidence
from authradar.scanner.rate_limit_tester import ProbeResponse, analyze_rate_limiting


def test_missing_rate_limit_high_confidence() -> None:
    finding = analyze_rate_limiting([ProbeResponse(status_code=200) for _ in range(12)])
    assert finding is not None
    assert finding.id == "AR-RATE-001"
    assert finding.confidence is Confidence.HIGH


def test_429_is_defended() -> None:
    probes = [ProbeResponse(status_code=200) for _ in range(4)]
    probes.append(ProbeResponse(status_code=429))
    assert analyze_rate_limiting(probes) is None


def test_lockout_phrase_is_defended() -> None:
    probes = [ProbeResponse(status_code=200, body="Too many attempts") for _ in range(6)]
    assert analyze_rate_limiting(probes) is None


def test_retry_after_is_defended() -> None:
    probes = [ProbeResponse(status_code=200, retry_after=True) for _ in range(6)]
    assert analyze_rate_limiting(probes) is None


def test_too_few_attempts_inconclusive() -> None:
    assert analyze_rate_limiting([ProbeResponse(status_code=200)] * 3) is None
