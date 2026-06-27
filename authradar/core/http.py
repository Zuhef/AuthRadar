"""HTTP capture models and parsing helpers.

Scanners never touch the network directly. Instead they analyse
:class:`CapturedResponse` objects produced by the request engine. This keeps
detection logic pure and unit-testable, and isolates all I/O in one place.

All parsing here treats input as untrusted (it originates from the scanned
target, which may be hostile) and never raises on malformed data.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class SameSite(StrEnum):
    """Normalised ``SameSite`` cookie attribute values."""

    STRICT = "Strict"
    LAX = "Lax"
    NONE = "None"


class ParsedCookie(BaseModel):
    """A cookie parsed from a single ``Set-Cookie`` response header.

    httpx's cookie jar discards security attributes, so AuthRadar parses the
    raw header itself to retain ``Secure`` / ``HttpOnly`` / ``SameSite``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    value: str
    secure: bool = False
    http_only: bool = False
    same_site: SameSite | None = None
    path: str | None = None
    domain: str | None = None
    max_age: int | None = None
    expires: str | None = None
    raw: str = ""


class CapturedRequest(BaseModel):
    """A normalised snapshot of an outbound request."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    method: str
    url: str
    headers: dict[str, str] = {}
    body: str | None = None


class CapturedResponse(BaseModel):
    """A normalised, immutable snapshot of an HTTP response.

    ``headers`` keys are lower-cased; duplicate headers are joined with
    ``", "`` per RFC 9110, except ``Set-Cookie`` which is preserved verbatim in
    :attr:`set_cookie` and parsed into :attr:`cookies`.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    url: str
    status_code: int
    headers: dict[str, str] = {}
    set_cookie: tuple[str, ...] = ()
    cookies: tuple[ParsedCookie, ...] = ()
    body: str = ""
    elapsed_ms: float = 0.0
    request: CapturedRequest | None = None

    def header(self, name: str) -> str | None:
        """Case-insensitive header lookup."""
        return self.headers.get(name.lower())

    @property
    def is_https(self) -> bool:
        """Whether the response URL was served over TLS."""
        return self.url.lower().startswith("https://")

    @property
    def content_type(self) -> str:
        """Lower-cased media type without parameters (empty if absent)."""
        raw = self.header("content-type") or ""
        return raw.split(";", 1)[0].strip().lower()

    @property
    def is_html(self) -> bool:
        """Whether the response looks like an HTML document."""
        return "html" in self.content_type


def _normalise_same_site(value: str) -> SameSite | None:
    """Map a raw ``SameSite`` value to the canonical enum, or ``None``."""
    folded = value.strip().lower()
    for member in SameSite:
        if member.value.lower() == folded:
            return member
    return None


def parse_set_cookie(header: str) -> ParsedCookie:
    """Parse one ``Set-Cookie`` header value into a :class:`ParsedCookie`.

    Robust against malformed/hostile input: never raises. Unknown attributes
    are ignored; a missing ``name=value`` pair yields an empty value.
    """
    raw = header
    segments = [segment.strip() for segment in header.split(";")]
    first = segments[0] if segments else ""
    name, sep, value = first.partition("=")
    name = name.strip()
    value = value.strip() if sep else ""

    secure = False
    http_only = False
    same_site: SameSite | None = None
    path: str | None = None
    domain: str | None = None
    max_age: int | None = None
    expires: str | None = None

    for segment in segments[1:]:
        if not segment:
            continue
        key, _, attr_value = segment.partition("=")
        key_l = key.strip().lower()
        attr_value = attr_value.strip()
        if key_l == "secure":
            secure = True
        elif key_l == "httponly":
            http_only = True
        elif key_l == "samesite":
            same_site = _normalise_same_site(attr_value)
        elif key_l == "path":
            path = attr_value or None
        elif key_l == "domain":
            domain = attr_value or None
        elif key_l == "expires":
            expires = attr_value or None
        elif key_l == "max-age":
            try:
                max_age = int(attr_value)
            except ValueError:
                max_age = None

    return ParsedCookie(
        name=name,
        value=value,
        secure=secure,
        http_only=http_only,
        same_site=same_site,
        path=path,
        domain=domain,
        max_age=max_age,
        expires=expires,
        raw=raw,
    )


def parse_set_cookies(headers: list[str]) -> tuple[ParsedCookie, ...]:
    """Parse every ``Set-Cookie`` header value into cookies."""
    return tuple(parse_set_cookie(h) for h in headers if h)
