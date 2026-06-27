"""Built-in authentication scanners.

Importing this package imports every scanner module, which registers each
scanner with the central registry via the ``@register_scanner`` decorator.
"""

from __future__ import annotations

from authradar.scanner import (
    account_enum_detector,
    csrf_auth_analyzer,
    jwt_analyzer,
    login_detector,
    mfa_validator,
    otp_analyzer,
    rate_limit_tester,
    reset_flow_analyzer,
    session_checker,
)

__all__ = [
    "account_enum_detector",
    "csrf_auth_analyzer",
    "jwt_analyzer",
    "login_detector",
    "mfa_validator",
    "otp_analyzer",
    "rate_limit_tester",
    "reset_flow_analyzer",
    "session_checker",
]
