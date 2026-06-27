"""Shared detection heuristics used by multiple scanners.

Pure, side-effect-free helpers for recognising session/auth cookies and
locating JWT-shaped strings in text. Kept conservative to limit false
positives.
"""

from __future__ import annotations

import re

from authradar.core.parsing import HtmlForm

# Substrings commonly found in session-cookie names across frameworks.
_SESSION_HINTS: tuple[str, ...] = (
    "session",
    "sess",
    "sessionid",
    "jsessionid",
    "phpsessid",
    "asp.net_sessionid",
    "aspsessionid",
    "connect.sid",
    "sid",
    "auth_session",
    "_session",
)

# Substrings indicating an authentication/bearer token cookie.
_AUTH_HINTS: tuple[str, ...] = (
    "auth",
    "token",
    "jwt",
    "access_token",
    "accesstoken",
    "refresh_token",
    "refreshtoken",
    "id_token",
    "bearer",
    "remember",
    "remember_token",
    "remember-me",
)

# CSRF cookie name hints (these are *expected* to be readable by JS, so they
# are excluded from HttpOnly findings).
_CSRF_HINTS: tuple[str, ...] = (
    "csrf",
    "xsrf",
    "_csrf",
    "csrftoken",
    "xsrf-token",
    "antiforgery",
)

# A JWT is three base64url segments separated by dots; the header and payload
# are base64url-encoded JSON objects, which always begin with ``eyJ``.
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def _name_matches(name: str, hints: tuple[str, ...]) -> bool:
    folded = name.strip().lower()
    return any(hint in folded for hint in hints)


def looks_like_session_cookie(name: str) -> bool:
    """Heuristically decide whether ``name`` denotes a session cookie."""
    return _name_matches(name, _SESSION_HINTS)


def looks_like_auth_cookie(name: str) -> bool:
    """Whether ``name`` denotes a session or authentication-token cookie."""
    return looks_like_session_cookie(name) or _name_matches(name, _AUTH_HINTS)


def looks_like_csrf_cookie(name: str) -> bool:
    """Whether ``name`` denotes a CSRF token cookie."""
    return _name_matches(name, _CSRF_HINTS)


def find_jwts(text: str) -> list[str]:
    """Return all JWT-shaped substrings in ``text`` (order-preserving, unique)."""
    seen: dict[str, None] = {}
    for match in JWT_RE.findall(text or ""):
        seen.setdefault(match, None)
    return list(seen)


# Body phrases that indicate the server is throttling / locking out requests.
THROTTLE_PHRASES: tuple[str, ...] = (
    "too many",
    "rate limit",
    "rate-limit",
    "try again later",
    "temporarily locked",
    "account locked",
    "account is locked",
    "slow down",
    "captcha",
)


def indicates_throttling(status_code: int, *, retry_after: bool, body: str) -> bool:
    """Whether a response signals rate limiting / lockout."""
    if status_code == 429 or retry_after:
        return True
    lowered = body.lower()
    return any(phrase in lowered for phrase in THROTTLE_PHRASES)


_NON_VALUE_INPUTS = frozenset({"submit", "button", "image", "reset"})
_IDENTIFIER_TYPES = frozenset({"email", "text", "tel"})


def build_login_payload(
    form: HtmlForm,
    username: str,
    password: str,
    *,
    username_field: str,
    password_field: str,
) -> dict[str, str]:
    """Build form data for a login POST, preserving hidden fields (e.g. CSRF).

    The identifier field is chosen as ``username_field`` if present, else the
    first text/email/tel control; the password field is the first password
    control, else ``password_field``.
    """
    data: dict[str, str] = {
        control.name: control.value
        for control in form.inputs
        if control.type.lower() not in _NON_VALUE_INPUTS
    }

    identifier = username_field if form.get_input(username_field) else None
    if identifier is None:
        candidate = next(
            (c for c in form.inputs if c.type.lower() in _IDENTIFIER_TYPES),
            None,
        )
        identifier = candidate.name if candidate else username_field
    data[identifier] = username

    password_input = form.input_by_type("password")
    data[password_input.name if password_input else password_field] = password
    return data
