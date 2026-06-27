"""Report rendering in JSON, Markdown and HTML."""

from __future__ import annotations

from authradar.core.exceptions import ConfigError
from authradar.core.models import ScanResult
from authradar.reporting.base import Reporter
from authradar.reporting.html_report import HtmlReporter
from authradar.reporting.json_report import JsonReporter
from authradar.reporting.markdown_report import MarkdownReporter

_REPORTERS: dict[str, Reporter] = {
    reporter.format_name: reporter
    for reporter in (JsonReporter(), MarkdownReporter(), HtmlReporter())
}


def available_formats() -> list[str]:
    """Return the supported report format names, sorted."""
    return sorted(_REPORTERS)


def get_reporter(format_name: str) -> Reporter:
    """Return the reporter for ``format_name`` or raise :class:`ConfigError`."""
    try:
        return _REPORTERS[format_name]
    except KeyError:
        msg = f"unknown report format {format_name!r}; choose from {available_formats()}"
        raise ConfigError(msg) from None


def render_report(result: ScanResult, format_name: str) -> str:
    """Render ``result`` in the requested format."""
    return get_reporter(format_name).render(result)


__all__ = [
    "HtmlReporter",
    "JsonReporter",
    "MarkdownReporter",
    "Reporter",
    "available_formats",
    "get_reporter",
    "render_report",
]
