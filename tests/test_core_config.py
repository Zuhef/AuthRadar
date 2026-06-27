"""Tests for authradar.core.config."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from authradar.core.config import ScanConfig


def test_target_gets_default_scheme() -> None:
    config = ScanConfig(target="example.com")
    assert config.target == "https://example.com"
    assert config.target_scheme == "https"
    assert config.target_host == "example.com"


def test_http_target_with_port_preserved() -> None:
    config = ScanConfig(target="http://Host.example:8080/path")
    assert config.target_scheme == "http"
    assert config.target_host == "host.example"


def test_scope_hosts_includes_allowed() -> None:
    config = ScanConfig(target="https://a.example", allowed_hosts=("B.example", "c.example"))
    assert config.scope_hosts() == {"a.example", "b.example", "c.example"}


def test_invalid_scheme_rejected() -> None:
    with pytest.raises(ValidationError):
        ScanConfig(target="ftp://example.com")


def test_empty_target_rejected() -> None:
    with pytest.raises(ValidationError):
        ScanConfig(target="   ")


def test_bounds_validation() -> None:
    with pytest.raises(ValidationError):
        ScanConfig(target="https://a.example", concurrency=0)
    with pytest.raises(ValidationError):
        ScanConfig(target="https://a.example", max_pages=0)
    with pytest.raises(ValidationError):
        ScanConfig(target="https://a.example", timeout_s=0.0)


def test_secure_defaults() -> None:
    config = ScanConfig(target="https://a.example")
    assert config.verify_tls is True
    assert config.active_probes is False
    assert config.use_browser is False
