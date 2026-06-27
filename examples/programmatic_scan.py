"""Example: run an AuthRadar scan programmatically and print a Markdown report.

Authorized use only. Usage:

    python examples/programmatic_scan.py https://example.com
"""

from __future__ import annotations

import asyncio
import sys

from authradar.core.config import ScanConfig
from authradar.engine import run_scan
from authradar.reporting import render_report


async def _run(target: str) -> int:
    config = ScanConfig(target=target)
    result = await run_scan(config)
    print(render_report(result, "markdown"))
    highest = result.summarize().highest_severity
    return 1 if highest is not None else 0


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python examples/programmatic_scan.py <target-url>", file=sys.stderr)
        return 2
    return asyncio.run(_run(sys.argv[1]))


if __name__ == "__main__":
    sys.exit(main())
