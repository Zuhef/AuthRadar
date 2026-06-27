"""Immutable result data models.

These models are the contract between scanners (which produce
:class:`Finding` objects) and reporters (which render them). Keeping them
immutable (``frozen=True``) makes findings safe to share across the async
scanner pipeline and hashable for de-duplication.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Severity of a finding, ordered from informational to critical."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric rank used for ordering and threshold comparisons."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(StrEnum):
    """How confident a scanner is that a finding is a true positive."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Category(StrEnum):
    """Functional category a finding belongs to."""

    LOGIN = "login"
    TRANSPORT = "transport"
    RATE_LIMITING = "rate_limiting"
    JWT = "jwt"
    OTP = "otp"
    SESSION = "session"
    PASSWORD_RESET = "password_reset"
    CSRF = "csrf"
    ACCOUNT_ENUMERATION = "account_enumeration"
    MFA = "mfa"
    OAUTH = "oauth"


class Finding(BaseModel):
    """A single security observation produced by a scanner.

    ``id`` is a stable check identifier (for example ``AR-COOKIE-001``) so that
    findings can be triaged and suppressed deterministically across runs.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: Category
    description: str
    remediation: str
    scanner: str
    location: str | None = None
    evidence: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    cwe: tuple[int, ...] = ()
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def fingerprint(self) -> str:
        """Stable identity for de-duplication (check id + location)."""
        return f"{self.id}@{self.location or '-'}"


class ScanSummary(BaseModel):
    """Aggregate counts for a completed scan."""

    model_config = ConfigDict(extra="forbid")

    total: int
    by_severity: dict[str, int]
    by_category: dict[str, int]
    highest_severity: Severity | None


class ScanResult(BaseModel):
    """The full result of a scan: findings plus run metadata."""

    model_config = ConfigDict(extra="forbid")

    target: str
    started_at: datetime
    finished_at: datetime
    duration_s: float
    findings: list[Finding]
    scanners_run: list[str]
    pages_crawled: int = 0
    errors: list[str] = Field(default_factory=list)

    def summarize(self) -> ScanSummary:
        """Compute aggregate counts over the findings."""
        by_sev: Counter[str] = Counter(f.severity.value for f in self.findings)
        by_cat: Counter[str] = Counter(f.category.value for f in self.findings)
        highest: Severity | None = None
        for finding in self.findings:
            if highest is None or finding.severity.rank > highest.rank:
                highest = finding.severity
        return ScanSummary(
            total=len(self.findings),
            by_severity=dict(by_sev),
            by_category=dict(by_cat),
            highest_severity=highest,
        )

    def sorted_findings(self) -> list[Finding]:
        """Findings ordered by descending severity, then by check id."""
        return sorted(
            self.findings,
            key=lambda f: (-f.severity.rank, f.id, f.location or ""),
        )
