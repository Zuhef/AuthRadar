"""Tests for the AuthRadar CLI."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime

import pytest

from authradar.cli.commands import (
    _exit_code,
    build_scan_config,
    cmd_list_scanners,
    cmd_version,
)
from authradar.cli.main import build_parser
from authradar.core.exceptions import ConfigError
from authradar.core.models import Category, Confidence, Finding, ScanResult, Severity


def _result_with(severity: Severity) -> ScanResult:
    now = datetime.now(UTC)
    finding = Finding(
        id="AR-T-001",
        title="t",
        severity=severity,
        confidence=Confidence.HIGH,
        category=Category.SESSION,
        description="d",
        remediation="r",
        scanner="s",
    )
    return ScanResult(
        target="https://t.example",
        started_at=now,
        finished_at=now,
        duration_s=0.0,
        findings=[finding],
        scanners_run=["s"],
    )


def test_parser_scan_defaults() -> None:
    args = build_parser().parse_args(["scan", "example.com"])
    assert args.command == "scan"
    assert args.target == "example.com"
    assert args.format == "markdown"
    assert args.fail_on == "high"


def test_build_scan_config_basic() -> None:
    args = build_parser().parse_args(["scan", "example.com", "--active", "--max-pages", "5"])
    config = build_scan_config(args)
    assert config.target == "https://example.com"
    assert config.active_probes is True
    assert config.max_pages == 5
    assert config.auth is None


def test_build_scan_config_requires_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AUTHRADAR_PASSWORD", raising=False)
    args = build_parser().parse_args(["scan", "example.com", "--username", "probeuser"])
    with pytest.raises(ConfigError):
        build_scan_config(args)


def test_build_scan_config_with_auth() -> None:
    args = build_parser().parse_args(
        ["scan", "https://e.com", "--username", "u", "--password", "p", "--protected-path", "/me"]
    )
    config = build_scan_config(args)
    assert config.auth is not None
    assert config.auth.valid is not None
    assert config.auth.valid.username == "u"
    assert config.auth.protected_path == "/me"


def test_exit_code_threshold() -> None:
    result = _result_with(Severity.HIGH)
    assert _exit_code(result, "high") == 1
    assert _exit_code(result, "critical") == 0
    assert _exit_code(result, "none") == 0


def test_cmd_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert cmd_version(argparse.Namespace()) == 0
    assert "authradar" in capsys.readouterr().out


def test_cmd_list_scanners(capsys: pytest.CaptureFixture[str]) -> None:
    assert cmd_list_scanners(argparse.Namespace(verbose=False)) == 0
    assert "jwt_analyzer" in capsys.readouterr().out
