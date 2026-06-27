"""Tests for authradar.reporting."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from authradar.core.exceptions import ConfigError
from authradar.core.models import Category, Confidence, Finding, ScanResult, Severity
from authradar.reporting import available_formats, get_reporter, render_report


def _finding(
    *,
    location: str | None = "cookie:SID",
    evidence: tuple[str, ...] = ("ev1",),
) -> Finding:
    return Finding(
        id="AR-T-001",
        title="Test finding",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SESSION,
        description="desc",
        remediation="fix it",
        scanner="tester",
        location=location,
        evidence=evidence,
        references=("https://example.com/ref",),
        cwe=(614,),
    )


def _result(*findings: Finding) -> ScanResult:
    now = datetime.now(UTC)
    return ScanResult(
        target="https://t.example",
        started_at=now,
        finished_at=now,
        duration_s=1.0,
        findings=list(findings),
        scanners_run=["tester"],
        pages_crawled=3,
    )


def test_available_formats() -> None:
    assert set(available_formats()) == {"json", "markdown", "html"}


def test_json_report_is_valid() -> None:
    data = json.loads(render_report(_result(_finding()), "json"))
    assert data["target"] == "https://t.example"
    assert data["summary"]["total"] == 1
    assert data["findings"][0]["id"] == "AR-T-001"
    assert data["findings"][0]["severity"] == "high"


def test_markdown_report_contains_finding() -> None:
    out = render_report(_result(_finding()), "markdown")
    assert "# AuthRadar report" in out
    assert "AR-T-001" in out
    assert "fix it" in out


def test_html_report_escapes_dynamic_content() -> None:
    malicious = "<script>alert(1)</script>"
    out = render_report(_result(_finding(location=malicious, evidence=(malicious,))), "html")
    assert malicious not in out
    assert "&lt;script&gt;" in out


def test_unknown_format_raises() -> None:
    with pytest.raises(ConfigError):
        get_reporter("pdf")
