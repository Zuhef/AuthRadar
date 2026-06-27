"""Tests for authradar.core.models."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from authradar.core.models import Category, Confidence, Finding, ScanResult, Severity


def _finding(check_id: str, severity: Severity, location: str | None = None) -> Finding:
    return Finding(
        id=check_id,
        title="t",
        severity=severity,
        confidence=Confidence.HIGH,
        category=Category.JWT,
        description="d",
        remediation="r",
        scanner="s",
        location=location,
    )


def test_severity_rank_ordering() -> None:
    ranks = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    assert [s.rank for s in ranks] == sorted(s.rank for s in ranks)
    assert Severity.CRITICAL.rank > Severity.INFO.rank


def test_finding_fingerprint_and_frozen() -> None:
    finding = _finding("AR-X-001", Severity.HIGH, "loc")
    assert finding.fingerprint == "AR-X-001@loc"
    frozen_field = "id"
    with pytest.raises(ValidationError):
        setattr(finding, frozen_field, "other")


def test_scan_result_summarize() -> None:
    now = datetime.now(UTC)
    result = ScanResult(
        target="https://a.example",
        started_at=now,
        finished_at=now,
        duration_s=1.0,
        findings=[
            _finding("AR-A-001", Severity.LOW),
            _finding("AR-B-001", Severity.CRITICAL),
            _finding("AR-C-001", Severity.MEDIUM),
        ],
        scanners_run=["s"],
    )
    summary = result.summarize()
    assert summary.total == 3
    assert summary.highest_severity is Severity.CRITICAL
    assert summary.by_severity["critical"] == 1
    ordered = result.sorted_findings()
    assert ordered[0].severity is Severity.CRITICAL
    assert ordered[-1].severity is Severity.LOW


def test_summarize_empty() -> None:
    now = datetime.now(UTC)
    result = ScanResult(
        target="https://a.example",
        started_at=now,
        finished_at=now,
        duration_s=0.0,
        findings=[],
        scanners_run=[],
    )
    assert result.summarize().highest_severity is None
