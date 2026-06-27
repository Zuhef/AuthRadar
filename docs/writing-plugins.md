# Writing a scanner plugin

AuthRadar scanners are discovered two ways:

1. **Built-in** — modules under `authradar/scanner/`, imported by that package's
   `__init__`.
2. **Third-party** — any installed package that advertises a scanner through the
   `authradar.scanners` entry-point group.

Both produce the same thing: a `BaseScanner` subclass registered with the
central registry.

## Anatomy of a scanner

Keep detection logic in **pure functions** and let the scanner class do the
collection. This is what makes AuthRadar testable.

```python
from __future__ import annotations

from typing import ClassVar

from authradar.core.models import Category, Confidence, Finding, Severity
from authradar.core.scanner_base import BaseScanner, ScanContext, register_scanner


def analyze_server_header(server: str | None) -> Finding | None:
    """Pure analysis: flag a server header that leaks its version."""
    if server and any(ch.isdigit() for ch in server):
        return Finding(
            id="EXT-INFO-001",
            title="Server version disclosed",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            category=Category.TRANSPORT,
            description="The Server header reveals software version information.",
            remediation="Suppress version details in the Server header.",
            scanner="server_header",
            evidence=(f"Server: {server}",),
            cwe=(200,),
        )
    return None


@register_scanner
class ServerHeaderScanner(BaseScanner):
    id: ClassVar[str] = "server_header"
    name: ClassVar[str] = "Server header analyzer"
    category: ClassVar[Category] = Category.TRANSPORT
    description: ClassVar[str] = "Flags version disclosure in the Server header."

    async def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for response in context.responses:
            finding = analyze_server_header(response.header("server"))
            if finding is not None:
                findings.append(finding)
        return findings
```

## What's in a `ScanContext`

| Attribute | Description |
| --- | --- |
| `config` | The `ScanConfig` for this run. |
| `engine` | The live `RequestEngine` for additional in-scope probing. |
| `responses` | Every `CapturedResponse` collected. |
| `parsed_pages` | Parsed HTML (`forms`, `links`, `inline_scripts`, ...). |
| `auth_flows` | Detected `AuthFlow` objects. |
| `storage` | Browser `localStorage`/`sessionStorage` snapshots (if `--browser`). |

Helpers: `context.flows_of(*types)`, `context.forms()`, `context.set_cookies()`,
`context.is_https_target`.

## Active probes

If your scanner sends extra traffic, gate it behind `context.config.active_probes`
and keep request counts bounded. Confine all requests to in-scope hosts (the
engine enforces this and raises `ScopeError` otherwise).

## Packaging a third-party scanner

In your plugin package's `pyproject.toml`:

```toml
[project.entry-points."authradar.scanners"]
server_header = "my_pkg.scanners:ServerHeaderScanner"
```

When installed alongside AuthRadar, `select_scanners()` will load and register it
automatically. Each entry point must resolve to a `BaseScanner` subclass or a
`PluginError` is raised.
