"""AuthRadar command-line entry point."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable

from authradar import __version__
from authradar.cli.commands import (
    cmd_list_scanners,
    cmd_scan,
    cmd_serve,
    cmd_version,
)
from authradar.reporting import available_formats

_FAIL_ON_CHOICES = ("none", "info", "low", "medium", "high", "critical")


def _add_scan_arguments(scan: argparse.ArgumentParser) -> None:
    scan.add_argument("target", help="Target base URL, e.g. https://example.com")
    scan.add_argument(
        "--format",
        choices=available_formats(),
        default="markdown",
        help="Report format (default: markdown).",
    )
    scan.add_argument("-o", "--output", help="Write the report to this file instead of stdout.")
    scan.add_argument("--max-pages", type=int, default=50, help="Maximum pages to crawl.")
    scan.add_argument("--max-depth", type=int, default=3, help="Maximum crawl depth.")
    scan.add_argument("--concurrency", type=int, default=10, help="Concurrent requests.")
    scan.add_argument("--timeout", type=float, default=15.0, help="Per-request timeout (seconds).")
    scan.add_argument("--probe-attempts", type=int, default=12, help="Active probe attempt count.")
    scan.add_argument(
        "--active",
        action="store_true",
        help="Enable active probes (rate-limit, OTP, enumeration, MFA). Authorised targets only.",
    )
    scan.add_argument(
        "--browser",
        action="store_true",
        help="Use Playwright to inspect localStorage/sessionStorage (requires a browser).",
    )
    scan.add_argument(
        "--insecure", action="store_true", help="Disable TLS certificate verification."
    )
    scan.add_argument(
        "--allow-host",
        action="append",
        metavar="HOST",
        help="Additional in-scope host (repeatable).",
    )
    scan.add_argument(
        "--enable", action="append", metavar="ID", help="Only run these scanner ids (repeatable)."
    )
    scan.add_argument(
        "--disable", action="append", metavar="ID", help="Skip these scanner ids (repeatable)."
    )
    scan.add_argument("--username", help="Identifier for an account you are authorised to test.")
    scan.add_argument("--password", help="Password (or set AUTHRADAR_PASSWORD).")
    scan.add_argument("--login-path", help="Path of the login endpoint.")
    scan.add_argument("--logout-path", help="Path of the logout endpoint.")
    scan.add_argument("--protected-path", help="Path of a resource that requires authentication.")
    scan.add_argument("--username-field", default="username", help="Login username field name.")
    scan.add_argument("--password-field", default="password", help="Login password field name.")
    scan.add_argument(
        "--fail-on",
        choices=_FAIL_ON_CHOICES,
        default="high",
        help="Exit non-zero if a finding at/above this severity is found (default: high).",
    )
    scan.add_argument("-q", "--quiet", action="store_true", help="Suppress the stderr summary.")


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="authradar",
        description="Asynchronous authentication security auditing framework.",
    )
    parser.add_argument("--version", action="version", version=f"authradar {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    _add_scan_arguments(
        subparsers.add_parser("scan", help="Audit a target's authentication surface.")
    )

    list_scanners = subparsers.add_parser("list-scanners", help="List available scanners.")
    list_scanners.add_argument(
        "-v", "--verbose", action="store_true", help="Show scanner descriptions."
    )

    serve = subparsers.add_parser("serve", help="Run the HTTP API server.")
    serve.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1).")
    serve.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000).")

    subparsers.add_parser("version", help="Print the AuthRadar version.")
    return parser


_COMMANDS: dict[str, Callable[[argparse.Namespace], int]] = {
    "scan": cmd_scan,
    "list-scanners": cmd_list_scanners,
    "serve": cmd_serve,
    "version": cmd_version,
}


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and dispatch to the selected command."""
    args = build_parser().parse_args(argv)
    handler = _COMMANDS[args.command]
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
