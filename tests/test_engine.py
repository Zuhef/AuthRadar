"""Integration tests for authradar.engine.run_scan."""

from __future__ import annotations

from authradar.core.config import AuthConfig, Credentials
from authradar.engine import run_scan
from tests.apps import VALID_PASSWORD, VALID_USER, build_vulnerable_app
from tests.helpers import asgi_client, make_config


async def test_passive_scan_finds_core_issues() -> None:
    config = make_config(active_probes=False)
    client = asgi_client(build_vulnerable_app())
    try:
        result = await run_scan(config, client=client)
    finally:
        await client.aclose()

    ids = {finding.id for finding in result.findings}
    assert "AR-CSRF-001" in ids
    assert "AR-LOGIN-001" in ids
    assert {"AR-COOKIE-002", "AR-COOKIE-003"} & ids
    assert result.pages_crawled > 0
    assert "session_checker" in result.scanners_run

    fingerprints = [finding.fingerprint for finding in result.findings]
    assert len(fingerprints) == len(set(fingerprints))


async def test_active_scan_finds_rate_limit() -> None:
    auth = AuthConfig(
        valid=Credentials(username=VALID_USER, password=VALID_PASSWORD),
        protected_path="/dashboard",
        logout_path="/logout",
    )
    config = make_config(active_probes=True, probe_attempts=8, auth=auth)
    client = asgi_client(build_vulnerable_app())
    try:
        result = await run_scan(config, client=client)
    finally:
        await client.aclose()

    ids = {finding.id for finding in result.findings}
    assert "AR-RATE-001" in ids


async def test_scoped_scanner_selection() -> None:
    config = make_config(enabled_scanners=("login_detector",))
    client = asgi_client(build_vulnerable_app())
    try:
        result = await run_scan(config, client=client)
    finally:
        await client.aclose()
    assert result.scanners_run == ["login_detector"]
