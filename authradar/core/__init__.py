"""Core building blocks: models, configuration, HTTP engine, and discovery."""

from __future__ import annotations

from authradar.core.config import AuthConfig, Credentials, ScanConfig
from authradar.core.exceptions import (
    AuthRadarError,
    BrowserUnavailableError,
    ConfigError,
    PluginError,
    RequestEngineError,
    ScopeError,
)
from authradar.core.models import (
    Category,
    Confidence,
    Finding,
    ScanResult,
    ScanSummary,
    Severity,
)

__all__ = [
    "AuthConfig",
    "AuthRadarError",
    "BrowserUnavailableError",
    "Category",
    "Confidence",
    "ConfigError",
    "Credentials",
    "Finding",
    "PluginError",
    "RequestEngineError",
    "ScanConfig",
    "ScanResult",
    "ScanSummary",
    "ScopeError",
    "Severity",
]
