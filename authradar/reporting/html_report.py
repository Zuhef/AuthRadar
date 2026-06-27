"""HTML reporter producing a standalone, self-contained report.

All dynamic content (target, locations, evidence) is HTML-escaped to prevent
report-viewing XSS from values that originate in the scanned application.
"""

from __future__ import annotations

from html import escape
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
_SEVERITY_COLORS = {
    Severity.CRITICAL: "#7b1d1d",
    Severity.HIGH: "#b3261e",
    Severity.MEDIUM: "#b26a00",
    Severity.LOW: "#1f6feb",
    Severity.INFO: "#5a5a5a",
}
_CSS = """
:root { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; }
body { margin: 0; padding: 2rem; color: #1b1b1b; background: #f6f7f9; }
h1 { font-size: 1.5rem; } h2 { margin-top: 2rem; }
.meta { color: #444; }
.badges { margin: 1rem 0; }
.badge { display: inline-block; padding: .25rem .6rem; border-radius: 999px;
         color: #fff; font-size: .8rem; margin-right: .4rem; }
.finding { background: #fff; border: 1px solid #e2e4e8; border-left-width: 6px;
           border-radius: 8px; padding: 1rem 1.25rem; margin: 1rem 0; }
.finding h3 { margin: 0 0 .5rem; font-size: 1.05rem; }
.finding .tag { display: inline-block; font-size: .75rem; color: #fff;
                padding: .1rem .5rem; border-radius: 4px; margin-right: .5rem; }
.kv { color: #555; font-size: .85rem; margin: .2rem 0; }
.evidence { background: #0d1117; color: #c9d1d9; padding: .6rem .8rem; border-radius: 6px;
            font-family: ui-monospace, Menlo, Consolas, monospace; font-size: .8rem;
            overflow-x: auto; white-space: pre-wrap; }
a { color: #1f6feb; }
.empty { color: #1a7f37; font-weight: 600; }
"""


class HtmlReporter(Reporter):
    """Render a scan result as a standalone HTML document."""

    format_name: ClassVar[str] = "html"
    file_extension: ClassVar[str] = "html"
    media_type: ClassVar[str] = "text/html"

    def render(self, result: ScanResult) -> str:
        summary = result.summarize()
        target = escape(result.target)
        badges = "".join(
            f'<span class="badge" style="background:{_SEVERITY_COLORS[sev]}">'
            f"{sev.value}: {summary.by_severity.get(sev.value, 0)}</span>"
            for sev in _SEVERITY_ORDER
        )
        findings_html = (
            '<p class="empty">No findings. ✅</p>'
            if not result.findings
            else "".join(self._render_finding(f) for f in result.sorted_findings())
        )
        errors_html = ""
        if result.errors:
            items = "".join(f"<li>{escape(error)}</li>" for error in result.errors)
            errors_html = f"<h2>Scan notes / errors</h2><ul>{items}</ul>"

        return (
            "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>"
            f"<title>AuthRadar report — {target}</title><style>{_CSS}</style></head><body>"
            f"<h1>AuthRadar report</h1>"
            f"<p class='meta'>Target: <strong>{target}</strong><br>"
            f"Scanned {escape(result.started_at.isoformat())} · "
            f"{result.duration_s:.2f}s · {result.pages_crawled} pages · "
            f"{summary.total} findings</p>"
            f"<div class='badges'>{badges}</div>"
            f"<h2>Findings</h2>{findings_html}{errors_html}"
            "</body></html>"
        )

    @staticmethod
    def _render_finding(finding: Finding) -> str:
        color = _SEVERITY_COLORS[finding.severity]
        severity_label = finding.severity.value.upper()
        rows = [
            f"<div class='kv'>Confidence: {escape(finding.confidence.value)} · "
            f"Category: {escape(finding.category.value)} · "
            f"Scanner: {escape(finding.scanner)}</div>"
        ]
        if finding.location:
            rows.append(f"<div class='kv'>Location: <code>{escape(finding.location)}</code></div>")
        if finding.cwe:
            cwe = ", ".join(f"CWE-{c}" for c in finding.cwe)
            rows.append(f"<div class='kv'>{escape(cwe)}</div>")
        evidence = ""
        if finding.evidence:
            joined = escape("\n".join(finding.evidence))
            evidence = f"<div class='evidence'>{joined}</div>"
        references = ""
        if finding.references:
            links = "".join(
                f"<li><a href='{escape(ref)}' rel='noopener noreferrer'>{escape(ref)}</a></li>"
                for ref in finding.references
            )
            references = f"<ul>{links}</ul>"
        return (
            f"<div class='finding' style='border-left-color:{color}'>"
            f"<h3><span class='tag' style='background:{color}'>{severity_label}</span>"
            f"{escape(finding.title)} <code>{escape(finding.id)}</code></h3>"
            f"{''.join(rows)}"
            f"<p>{escape(finding.description)}</p>"
            f"<p><strong>Remediation:</strong> {escape(finding.remediation)}</p>"
            f"{evidence}{references}</div>"
        )
