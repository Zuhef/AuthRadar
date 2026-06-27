"""JSON reporter producing machine-readable output for CI and tooling."""

from __future__ import annotations

import json
from typing import ClassVar

from authradar import __version__
from authradar.core.models import ScanResult
from authradar.reporting.base import Reporter


class JsonReporter(Reporter):
    """Serialise a scan result to stable, pretty-printed JSON."""

    format_name: ClassVar[str] = "json"
    file_extension: ClassVar[str] = "json"
    media_type: ClassVar[str] = "application/json"

    def render(self, result: ScanResult) -> str:
        summary = result.summarize()
        payload = {
            "tool": "authradar",
            "version": __version__,
            "target": result.target,
            "started_at": result.started_at.isoformat(),
            "finished_at": result.finished_at.isoformat(),
            "duration_s": round(result.duration_s, 3),
            "pages_crawled": result.pages_crawled,
            "scanners_run": result.scanners_run,
            "summary": summary.model_dump(mode="json"),
            "findings": [finding.model_dump(mode="json") for finding in result.sorted_findings()],
            "errors": result.errors,
        }
        return json.dumps(payload, indent=2)
