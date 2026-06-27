"""Markdown reporter producing a human-readable report."""

from __future__ import annotations

from typing import ClassVar

from authradar.core.models import Finding, ScanResult, Severity
from authradar.reporting.base import Reporter

_SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


class MarkdownReporter(Reporter):
    """Render a scan result as Markdown."""

    format_name: ClassVar[str] = "markdown"
    file_extension: ClassVar[str] = "md"
    media_type: ClassVar[str] = "text/markdown"

    def render(self, result: ScanResult) -> str:
        summary = result.summarize()
        lines: list[str] = [
            f"# AuthRadar report — {result.target}",
            "",
            f"- Scanned: {result.started_at.isoformat()}",
            f"- Duration: {result.duration_s:.2f}s",
            f"- Pages analysed: {result.pages_crawled}",
            f"- Scanners: {', '.join(result.scanners_run) or 'none'}",
            f"- Total findings: {summary.total}",
            "",
            "## Summary by severity",
            "",
            "| Severity | Count |",
            "| --- | --- |",
        ]
        for severity in _SEVERITY_ORDER:
            count = summary.by_severity.get(severity.value, 0)
            lines.append(f"| {severity.value} | {count} |")
        lines.append("")

        if not result.findings:
            lines.extend(["## Findings", "", "No findings. ✅", ""])
        else:
            lines.extend(["## Findings", ""])
            for finding in result.sorted_findings():
                lines.extend(self._render_finding(finding))

        if result.errors:
            lines.extend(["## Scan notes / errors", ""])
            lines.extend(f"- {error}" for error in result.errors)
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _render_finding(finding: Finding) -> list[str]:
        block = [
            f"### [{finding.severity.value.upper()}] {finding.title} (`{finding.id}`)",
            "",
            f"- Confidence: {finding.confidence.value}",
            f"- Category: {finding.category.value}",
            f"- Scanner: {finding.scanner}",
        ]
        if finding.location:
            block.append(f"- Location: `{finding.location}`")
        if finding.cwe:
            block.append(f"- CWE: {', '.join(f'CWE-{cwe}' for cwe in finding.cwe)}")
        block.extend(["", finding.description, "", f"**Remediation:** {finding.remediation}", ""])
        if finding.evidence:
            block.append("**Evidence:**")
            block.append("")
            block.extend(f"- `{item}`" for item in finding.evidence)
            block.append("")
        if finding.references:
            block.append("**References:**")
            block.append("")
            block.extend(f"- {ref}" for ref in finding.references)
            block.append("")
        return block
