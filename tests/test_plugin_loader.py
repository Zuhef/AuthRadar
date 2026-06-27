"""Tests for authradar.core.plugin_loader and the scanner registry."""

from __future__ import annotations

import pytest

from authradar.core.config import ScanConfig
from authradar.core.exceptions import ConfigError, PluginError
from authradar.core.models import Finding
from authradar.core.plugin_loader import load_builtin_scanners, select_scanners
from authradar.core.scanner_base import (
    BaseScanner,
    ScanContext,
    register_scanner,
    registered_scanners,
)


def test_builtin_scanners_register() -> None:
    load_builtin_scanners()
    ids = set(registered_scanners())
    expected = {
        "account_enum_detector",
        "csrf_auth_analyzer",
        "jwt_analyzer",
        "login_detector",
        "mfa_validator",
        "otp_analyzer",
        "rate_limit_tester",
        "reset_flow_analyzer",
        "session_checker",
    }
    assert expected <= ids


def test_select_enabled_and_disabled() -> None:
    config = ScanConfig(
        target="https://t.example",
        enabled_scanners=("jwt_analyzer", "session_checker"),
        disabled_scanners=("session_checker",),
    )
    selected = [scanner.id for scanner in select_scanners(config)]
    assert selected == ["jwt_analyzer"]


def test_select_unknown_scanner_raises() -> None:
    config = ScanConfig(target="https://t.example", enabled_scanners=("does_not_exist",))
    with pytest.raises(ConfigError):
        select_scanners(config)


def test_register_scanner_requires_id() -> None:
    class _NoId(BaseScanner):
        async def scan(self, context: ScanContext) -> list[Finding]:
            return []

    with pytest.raises(PluginError):
        register_scanner(_NoId)
