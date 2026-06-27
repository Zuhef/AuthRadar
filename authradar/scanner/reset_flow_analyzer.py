"""Password-reset token analysis.

Pure analyzers assess reset-token strength (keyspace and diversity), token
replay, excessive lifetime, and sequential/predictable generation. The scanner
passively extracts reset tokens that appear in observed URLs/links and analyses
their strength (it never requests password changes).
"""

from __future__ import annotations

import math
from collections import Counter
from itertools import pairwise
from typing import ClassVar
from urllib.parse import parse_qs, urlsplit

from authradar.core.models import Category, Confidence, Finding, Severity
from authradar.core.scanner_base import BaseScanner, ScanContext, register_scanner

_SCANNER = "reset_flow_analyzer"
_MIN_TOKEN_BITS = 64.0
_MIN_SHANNON_PER_CHAR = 2.0
_MIN_TOKEN_LEN = 8
_MAX_TTL_SECONDS = 60 * 60  # 1 hour
_TOKEN_PARAMS = frozenset(
    {"token", "reset_token", "code", "key", "t", "verification_token", "reset", "auth"}
)
_REFS = ("https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html",)


def _charset_size(token: str) -> int:
    size = 0
    if any(c.islower() for c in token):
        size += 26
    if any(c.isupper() for c in token):
        size += 26
    if any(c.isdigit() for c in token):
        size += 10
    if any(c in "-_" for c in token):
        size += 2
    if any(not c.isalnum() and c not in "-_" for c in token):
        size += 16
    return max(size, 1)


def estimate_token_entropy_bits(token: str) -> float:
    """Approximate keyspace entropy in bits (length x log2(charset size))."""
    if not token:
        return 0.0
    return len(token) * math.log2(_charset_size(token))


def shannon_entropy(token: str) -> float:
    """Per-character Shannon entropy (bits), detecting repetitive tokens."""
    if not token:
        return 0.0
    counts = Counter(token)
    total = len(token)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _token_preview(token: str) -> str:
    return f"{token[:4]}...({len(token)} chars)" if len(token) > 4 else f"({len(token)} chars)"


def analyze_reset_token(
    token: str,
    *,
    location: str | None = None,
    min_bits: float = _MIN_TOKEN_BITS,
) -> Finding | None:
    """Flag a weak reset token (low keyspace or low character diversity)."""
    if not token:
        return None
    bits = estimate_token_entropy_bits(token)
    low_keyspace = bits < min_bits
    low_diversity = len(token) >= _MIN_TOKEN_LEN and shannon_entropy(token) < _MIN_SHANNON_PER_CHAR
    if not (low_keyspace or low_diversity):
        return None
    reason = "low keyspace" if low_keyspace else "low character diversity"
    return Finding(
        id="AR-RESET-001",
        title="Weak password-reset token",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.PASSWORD_RESET,
        description=(
            f"A password-reset token appears weak ({reason}, ~{bits:.0f} bits). Predictable "
            "or low-entropy reset tokens can be guessed, letting an attacker take over "
            "accounts via the reset flow."
        ),
        remediation=(
            "Generate reset tokens from a cryptographically secure RNG with at least 128 "
            "bits of entropy, single-use and short-lived."
        ),
        scanner=_SCANNER,
        location=location,
        evidence=(f"token {_token_preview(token)}, ~{bits:.0f} bits, reason: {reason}",),
        references=_REFS,
        cwe=(330, 640),
    )


def analyze_token_sequence(tokens: list[str], *, location: str | None = None) -> Finding | None:
    """Flag sequential/predictable tokens (e.g. incrementing integers)."""
    numeric = [t for t in tokens if t.isdigit()]
    if len(numeric) < 2:
        return None
    values = sorted(int(t) for t in numeric)
    diffs = {b - a for a, b in pairwise(values)}
    if diffs and diffs <= {0, 1}:
        return Finding(
            id="AR-RESET-004",
            title="Predictable (sequential) reset tokens",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            category=Category.PASSWORD_RESET,
            description=(
                "Observed reset tokens are sequential integers. An attacker can predict "
                "the next token and hijack pending resets."
            ),
            remediation="Use cryptographically random, non-sequential reset tokens.",
            scanner=_SCANNER,
            location=location,
            evidence=(f"{len(numeric)} sequential numeric tokens observed",),
            references=_REFS,
            cwe=(340,),
        )
    return None


def analyze_token_replay(
    *,
    first_use_accepted: bool,
    second_use_accepted: bool,
    location: str | None = None,
) -> Finding | None:
    """Flag reset-token replay: a token still works after it was already used."""
    if first_use_accepted and second_use_accepted:
        return Finding(
            id="AR-RESET-002",
            title="Password-reset token can be replayed",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=Category.PASSWORD_RESET,
            description=(
                "A reset token remained valid after being used once. Reusable reset tokens "
                "let an attacker who captures a used token reset the password again."
            ),
            remediation="Invalidate reset tokens immediately on first successful use.",
            scanner=_SCANNER,
            location=location,
            evidence=("token accepted on both first and second use",),
            references=_REFS,
            cwe=(640,),
        )
    return None


def analyze_token_lifetime(
    ttl_seconds: float,
    *,
    location: str | None = None,
    max_ttl_seconds: float = _MAX_TTL_SECONDS,
) -> Finding | None:
    """Flag a reset token whose validity window is excessively long."""
    if ttl_seconds > max_ttl_seconds:
        return Finding(
            id="AR-RESET-003",
            title="Long-lived password-reset token",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            category=Category.PASSWORD_RESET,
            description=(
                f"Reset tokens remain valid for ~{int(ttl_seconds // 3600)}h. Long validity "
                "windows widen the opportunity for a leaked token to be abused."
            ),
            remediation="Expire reset tokens quickly (15-60 minutes) and on first use.",
            scanner=_SCANNER,
            location=location,
            evidence=(f"token TTL ~{int(ttl_seconds)}s",),
            references=_REFS,
            cwe=(640,),
        )
    return None


def extract_reset_tokens(url: str) -> list[str]:
    """Extract token-like query values from a URL relevant to password reset."""
    parts = urlsplit(url)
    path_is_reset = any(
        keyword in parts.path.lower() for keyword in ("reset", "forgot", "recover", "password")
    )
    tokens: list[str] = []
    for name, values in parse_qs(parts.query).items():
        if name.lower() in _TOKEN_PARAMS or path_is_reset:
            tokens.extend(value for value in values if len(value) >= _MIN_TOKEN_LEN)
    return tokens


@register_scanner
class ResetFlowAnalyzerScanner(BaseScanner):
    """Analyses any reset tokens observed in URLs/links for weakness."""

    id: ClassVar[str] = "reset_flow_analyzer"
    name: ClassVar[str] = "Password-reset flow analyzer"
    category: ClassVar[Category] = Category.PASSWORD_RESET
    description: ClassVar[str] = "Analyses reset-token strength and predictability."

    async def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        observed: list[str] = []

        urls = [response.url for response in context.responses]
        urls.extend(link for page in context.parsed_pages for link in page.links)

        analysed: set[str] = set()
        for url in urls:
            for token in extract_reset_tokens(url):
                observed.append(token)
                if token in analysed:
                    continue
                analysed.add(token)
                finding = analyze_reset_token(token, location=url)
                if finding is not None:
                    findings.append(finding)

        sequence_finding = analyze_token_sequence(observed)
        if sequence_finding is not None:
            findings.append(sequence_finding)
        return findings
