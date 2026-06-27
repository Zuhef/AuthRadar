"""Scan configuration with validation and secure defaults.

Defaults are conservative: TLS verification on, active probing off, crawling
bounded, and requests confined to the target host unless explicitly widened.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from authradar import __version__

DEFAULT_USER_AGENT = f"AuthRadar/{__version__} (+https://github.com/authradar/authradar)"
_ALLOWED_SCHEMES = frozenset({"http", "https"})


class Credentials(BaseModel):
    """A username/password pair for an account the operator is authorised to use."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    username: str
    password: str


class AuthConfig(BaseModel):
    """Optional knowledge about the target's authentication endpoints.

    Supplying credentials enables stateful checks (session fixation, logout
    invalidation). Only ever use accounts you own or are authorised to test.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    login_path: str | None = None
    logout_path: str | None = None
    protected_path: str | None = None
    username_field: str = "username"
    password_field: str = "password"
    valid: Credentials | None = None
    invalid_username: str = "authradar-unknown-user"


class ScanConfig(BaseModel):
    """Top-level scan configuration.

    The ``target`` is normalised to include a scheme. ``active_probes`` gates
    any check that sends more than baseline traffic (for example rate-limit
    probing); it is off by default so a scan is passive unless opted in.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    target: str
    max_pages: int = Field(default=50, ge=1, le=10_000)
    max_depth: int = Field(default=3, ge=0, le=20)
    concurrency: int = Field(default=10, ge=1, le=100)
    timeout_s: float = Field(default=15.0, gt=0.0, le=300.0)
    max_redirects: int = Field(default=5, ge=0, le=20)
    user_agent: str = DEFAULT_USER_AGENT
    verify_tls: bool = True
    follow_redirects: bool = True
    use_browser: bool = False
    allowed_hosts: tuple[str, ...] = ()
    active_probes: bool = False
    probe_attempts: int = Field(default=12, ge=2, le=100)
    enabled_scanners: tuple[str, ...] | None = None
    disabled_scanners: tuple[str, ...] = ()
    auth: AuthConfig | None = None

    @field_validator("target")
    @classmethod
    def _normalise_target(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate:
            msg = "target must not be empty"
            raise ValueError(msg)
        if "://" not in candidate:
            candidate = f"https://{candidate}"
        parts = urlsplit(candidate)
        if parts.scheme not in _ALLOWED_SCHEMES:
            msg = f"target scheme must be http or https, got {parts.scheme!r}"
            raise ValueError(msg)
        if not parts.hostname:
            msg = "target must include a host"
            raise ValueError(msg)
        return candidate

    @property
    def target_scheme(self) -> str:
        """Scheme of the target URL (``http`` or ``https``)."""
        return urlsplit(self.target).scheme

    @property
    def target_host(self) -> str:
        """Lower-cased hostname of the target URL."""
        host = urlsplit(self.target).hostname
        return host.lower() if host else ""

    def scope_hosts(self) -> frozenset[str]:
        """The set of hostnames requests are permitted to reach."""
        hosts = {self.target_host}
        hosts.update(h.strip().lower() for h in self.allowed_hosts if h.strip())
        return frozenset(hosts)
