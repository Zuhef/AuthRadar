"""Implementations of the AuthRadar CLI commands.

Argument parsing lives in :mod:`authradar.cli.main`; this module contains the
behaviour so it can be unit-tested without spawning a process.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

import uvicorn
from pydantic import ValidationError

from authradar import __version__
from authradar.api import API_KEY_ENV, create_app
from authradar.core.config import AuthConfig, Credentials, ScanConfig
from authradar.core.exceptions import AuthRadarError, ConfigError
from authradar.core.models import ScanResult, Severity
from authradar.core.plugin_loader import load_builtin_scanners
from authradar.core.scanner_base import registered_scanners
from authradar.engine import run_scan
from authradar.reporting import render_report

_PASSWORD_ENV = "AUTHRADAR_PASSWORD"
_SEVERITY_DISPLAY = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


def _build_auth_config(args: argparse.Namespace) -> AuthConfig | None:
    username: str | None = args.username
    if username is None:
        return None
    password: str | None = args.password or os.environ.get(_PASSWORD_ENV)
    if not password:
        msg = f"--username given but no password (use --password or ${_PASSWORD_ENV})"
        raise ConfigError(msg)
    return AuthConfig(
        login_path=args.login_path,
        logout_path=args.logout_path,
        protected_path=args.protected_path,
        username_field=args.username_field,
        password_field=args.password_field,
        valid=Credentials(username=username, password=password),
    )


def build_scan_config(args: argparse.Namespace) -> ScanConfig:
    """Translate parsed CLI arguments into a validated :class:`ScanConfig`."""
    return ScanConfig(
        target=args.target,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        concurrency=args.concurrency,
        timeout_s=args.timeout,
        active_probes=args.active,
        use_browser=args.browser,
        verify_tls=not args.insecure,
        allowed_hosts=tuple(args.allow_host or ()),
        probe_attempts=args.probe_attempts,
        enabled_scanners=tuple(args.enable) if args.enable else None,
        disabled_scanners=tuple(args.disable or ()),
        auth=_build_auth_config(args),
    )


def _exit_code(result: ScanResult, fail_on: str) -> int:
    if fail_on == "none":
        return 0
    threshold = Severity(fail_on)
    highest = result.summarize().highest_severity
    return 1 if highest is not None and highest.rank >= threshold.rank else 0


def _print_summary(result: ScanResult) -> None:
    summary = result.summarize()
    parts = [f"{sev.value}={summary.by_severity.get(sev.value, 0)}" for sev in _SEVERITY_DISPLAY]
    print(
        f"AuthRadar: {summary.total} findings ({', '.join(parts)}) "
        f"across {result.pages_crawled} pages in {result.duration_s:.2f}s",
        file=sys.stderr,
    )
    if result.errors:
        print(f"AuthRadar: {len(result.errors)} scan note(s)/error(s)", file=sys.stderr)


def cmd_scan(args: argparse.Namespace) -> int:
    """Run a scan and emit a report. Returns the process exit code."""
    try:
        config = build_scan_config(args)
    except (ConfigError, ValidationError) as exc:
        print(f"error: invalid configuration: {exc}", file=sys.stderr)
        return 2

    try:
        result = asyncio.run(run_scan(config))
    except AuthRadarError as exc:
        print(f"error: scan failed: {exc}", file=sys.stderr)
        return 2

    report = render_report(result, args.format)
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        if not args.quiet:
            print(f"report written to {args.output}", file=sys.stderr)
    else:
        print(report)

    if not args.quiet:
        _print_summary(result)
    return _exit_code(result, args.fail_on)


def cmd_list_scanners(args: argparse.Namespace) -> int:
    """List the registered scanners."""
    load_builtin_scanners()
    for scanner_id, scanner_cls in sorted(registered_scanners().items()):
        print(f"{scanner_id:24} {scanner_cls.category.value:20} {scanner_cls.name}")
        if args.verbose:
            print(f"    {scanner_cls.description}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Run the FastAPI server."""
    if not os.environ.get(API_KEY_ENV):
        print(
            f"warning: {API_KEY_ENV} is not set; the scan endpoints will return 503 "
            "until you set it.",
            file=sys.stderr,
        )
    print(f"AuthRadar web console: http://{args.host}:{args.port}/ui/", file=sys.stderr)
    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="info")
    return 0


def cmd_version(_args: argparse.Namespace) -> int:
    """Print the AuthRadar version."""
    print(f"authradar {__version__}")
    return 0
