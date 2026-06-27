"""Exception hierarchy for AuthRadar.

All recoverable errors derive from :class:`AuthRadarError` so callers can catch
the whole family without bare ``except Exception``.
"""

from __future__ import annotations


class AuthRadarError(Exception):
    """Base class for every error raised by AuthRadar."""


class ConfigError(AuthRadarError):
    """Raised when user-supplied configuration is invalid."""


class ScopeError(AuthRadarError):
    """Raised when a request would target a host outside the allowed scope.

    This is a deliberate safety guard against scope-escape / SSRF via
    attacker-controlled redirects or crawled links.
    """


class RequestEngineError(AuthRadarError):
    """Raised when the HTTP request engine fails irrecoverably."""


class PluginError(AuthRadarError):
    """Raised when a scanner plugin cannot be loaded or registered."""


class BrowserUnavailableError(AuthRadarError):
    """Raised when browser-based collection is requested but Playwright (or a
    browser binary) is not available in the environment."""
