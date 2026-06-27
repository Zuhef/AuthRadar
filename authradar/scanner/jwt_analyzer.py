"""JWT and token-storage analysis.

Decodes JWTs *without* verifying signatures (we don't hold the key) and flags
structural weaknesses: ``alg=none``, missing/excessive expiry, sensitive claims,
and tokens stored or leaked insecurely (localStorage, URLs).
"""

from __future__ import annotations

import base64
import binascii
import json
import time
from dataclasses import dataclass
from typing import Any, ClassVar
from urllib.parse import parse_qs, urlsplit

from authradar.core.models import Category, Confidence, Finding, Severity
from authradar.core.scanner_base import BaseScanner, BrowserStorage, ScanContext, register_scanner
from authradar.scanner.heuristics import find_jwts

_SCANNER = "jwt_analyzer"
_DEFAULT_MAX_LIFETIME_S = 24 * 60 * 60  # 24h is generous for an access token
_SENSITIVE_CLAIMS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "ssn",
        "credit_card",
        "creditcard",
        "card_number",
        "cvv",
        "api_key",
        "apikey",
        "private_key",
    }
)
_AUTH_KEY_HINTS = ("token", "jwt", "auth", "access", "refresh", "bearer", "id_token")
_REFS = (
    "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
    "https://datatracker.ietf.org/doc/html/rfc7519",
)


@dataclass(slots=True)
class DecodedJwt:
    """A decoded (unverified) JWT."""

    header: dict[str, Any]
    payload: dict[str, Any]
    signature: str
    raw: str

    @property
    def alg(self) -> str | None:
        value = self.header.get("alg")
        return value if isinstance(value, str) else None


def _b64url_decode(segment: str) -> bytes | None:
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except (binascii.Error, ValueError):
        return None


def _decode_json_segment(segment: str) -> dict[str, Any] | None:
    raw = _b64url_decode(segment)
    if raw is None:
        return None
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return {str(key): value for key, value in data.items()}


def decode_jwt(token: str) -> DecodedJwt | None:
    """Decode a JWT's header and payload, or return ``None`` if malformed."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header = _decode_json_segment(parts[0])
    payload = _decode_json_segment(parts[1])
    if header is None or payload is None:
        return None
    return DecodedJwt(header=header, payload=payload, signature=parts[2], raw=token)


def _token_preview(token: str) -> str:
    return token[:16] + "..." if len(token) > 16 else token


def _as_epoch(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def analyze_jwt_claims(
    decoded: DecodedJwt,
    *,
    location: str | None,
    now: float | None = None,
    max_lifetime_s: int = _DEFAULT_MAX_LIFETIME_S,
) -> list[Finding]:
    """Inspect a decoded JWT's claims for structural weaknesses."""
    findings: list[Finding] = []
    current = time.time() if now is None else now
    preview = _token_preview(decoded.raw)

    alg = decoded.alg
    if alg is not None and alg.lower() == "none":
        findings.append(
            Finding(
                id="AR-JWT-001",
                title="JWT accepts 'none' algorithm",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category=Category.JWT,
                description=(
                    "A JWT was issued with the 'none' algorithm, meaning it carries no "
                    "signature. Anyone can forge a valid token and impersonate any user."
                ),
                remediation=(
                    "Reject the 'none' algorithm server-side and pin verification to a "
                    "strong asymmetric or HMAC algorithm (e.g. RS256/ES256)."
                ),
                scanner=_SCANNER,
                location=location,
                evidence=(f"alg=none in token {preview}",),
                references=_REFS,
                cwe=(347,),
            )
        )

    exp = _as_epoch(decoded.payload.get("exp"))
    iat = _as_epoch(decoded.payload.get("iat"))
    if exp is None:
        findings.append(
            Finding(
                id="AR-JWT-002",
                title="JWT has no expiration claim",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category=Category.JWT,
                description=(
                    "The JWT has no 'exp' claim, so it never expires. A leaked token "
                    "remains valid indefinitely."
                ),
                remediation="Always set a short 'exp' on access tokens and rotate refresh tokens.",
                scanner=_SCANNER,
                location=location,
                evidence=(f"no exp claim in token {preview}",),
                references=_REFS,
                cwe=(613,),
            )
        )
    else:
        lifetime = exp - iat if iat is not None else exp - current
        if lifetime > max_lifetime_s:
            findings.append(
                Finding(
                    id="AR-JWT-003",
                    title="JWT is long-lived",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    category=Category.JWT,
                    description=(
                        f"The JWT is valid for roughly {int(lifetime // 3600)}h, far longer "
                        "than recommended for an access token. Long lifetimes widen the window "
                        "for token theft and replay."
                    ),
                    remediation=(
                        "Keep access-token lifetimes short (minutes) and use refresh tokens "
                        "with rotation for longer sessions."
                    ),
                    scanner=_SCANNER,
                    location=location,
                    evidence=(f"lifetime~{int(lifetime)}s in token {preview}",),
                    references=_REFS,
                    cwe=(613,),
                )
            )

    sensitive = sorted({key for key in decoded.payload if key.lower() in _SENSITIVE_CLAIMS})
    if sensitive:
        findings.append(
            Finding(
                id="AR-JWT-004",
                title="JWT payload contains sensitive data",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.JWT,
                description=(
                    "The JWT payload carries sensitive fields. JWT payloads are only "
                    "base64-encoded, not encrypted, so anyone who sees the token can read them."
                ),
                remediation=(
                    "Never place secrets or PII in a JWT payload. Store only opaque "
                    "identifiers and look up sensitive data server-side."
                ),
                scanner=_SCANNER,
                location=location,
                evidence=(f"sensitive claims: {', '.join(sensitive)}",),
                references=_REFS,
                cwe=(522,),
            )
        )

    return findings


def analyze_token_storage(storage: BrowserStorage) -> list[Finding]:
    """Flag JWTs (and likely auth tokens) persisted in web storage."""
    findings: list[Finding] = []
    findings.extend(
        _storage_finding(storage.url, key, value, persistent=True)
        for key, value in storage.local_storage.items()
        if _is_auth_storage_entry(key, value)
    )
    findings.extend(
        _storage_finding(storage.url, key, value, persistent=False)
        for key, value in storage.session_storage.items()
        if _is_auth_storage_entry(key, value)
    )
    return findings


def _is_auth_storage_entry(key: str, value: str) -> bool:
    if find_jwts(value):
        return True
    return any(hint in key.lower() for hint in _AUTH_KEY_HINTS)


def _storage_finding(url: str, key: str, value: str, *, persistent: bool) -> Finding:
    store = "localStorage" if persistent else "sessionStorage"
    severity = Severity.MEDIUM if persistent else Severity.LOW
    check_id = "AR-JWT-005" if persistent else "AR-JWT-006"
    has_jwt = bool(find_jwts(value))
    kind = "JWT" if has_jwt else "auth token"
    return Finding(
        id=check_id,
        title=f"{kind} stored in {store}",
        severity=severity,
        confidence=Confidence.MEDIUM,
        category=Category.JWT,
        description=(
            f"An {kind} was found in {store}, which is readable by any JavaScript on the "
            "page. A single XSS flaw can exfiltrate it. Tokens in cookies with HttpOnly are "
            "not exposed this way."
        ),
        remediation=(
            "Store session/auth tokens in cookies marked HttpOnly, Secure and SameSite "
            "rather than in web storage."
        ),
        scanner=_SCANNER,
        location=url,
        evidence=(f"{store}['{key}'] holds an {kind}",),
        references=_REFS,
        cwe=(922,),
    )


def analyze_url_for_jwt(url: str) -> list[Finding]:
    """Flag JWTs leaked in a URL path or query string."""
    query = urlsplit(url).query
    haystack = f"{urlsplit(url).path}?{query}" if query else urlsplit(url).path
    if not find_jwts(haystack):
        return []
    return [
        Finding(
            id="AR-JWT-007",
            title="JWT leaked in URL",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            category=Category.JWT,
            description=(
                "A JWT appears in a URL. URLs are logged by servers, proxies and browser "
                "history, and leak via the Referer header, exposing the token."
            ),
            remediation="Transmit tokens in headers or secure cookies, never in URLs.",
            scanner=_SCANNER,
            location=url,
            evidence=("JWT present in URL query/path",),
            references=_REFS,
            cwe=(598,),
        )
    ]


def _query_jwts(url: str) -> list[str]:
    values: list[str] = []
    for items in parse_qs(urlsplit(url).query).values():
        for item in items:
            values.extend(find_jwts(item))
    return values


@register_scanner
class JwtAnalyzerScanner(BaseScanner):
    """Locates JWTs across storage, URLs and responses and analyses them."""

    id: ClassVar[str] = "jwt_analyzer"
    name: ClassVar[str] = "JWT & token storage analyzer"
    category: ClassVar[Category] = Category.JWT
    description: ClassVar[str] = "Analyses JWTs and where auth tokens are stored."

    async def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        analysed: set[str] = set()

        def analyse_token(token: str, location: str | None) -> None:
            decoded = decode_jwt(token)
            if decoded is None or token in analysed:
                return
            analysed.add(token)
            findings.extend(analyze_jwt_claims(decoded, location=location))

        for storage in context.storage:
            findings.extend(analyze_token_storage(storage))
            for value in (*storage.local_storage.values(), *storage.session_storage.values()):
                for token in find_jwts(value):
                    analyse_token(token, storage.url)

        for response in context.responses:
            findings.extend(analyze_url_for_jwt(response.url))
            for token in _query_jwts(response.url):
                analyse_token(token, response.url)
            for token in find_jwts(response.body):
                analyse_token(token, response.url)

        for page in context.parsed_pages:
            for script in page.inline_scripts:
                for token in find_jwts(script):
                    analyse_token(token, page.url)

        return findings
