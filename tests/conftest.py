"""Pytest fixtures for the AuthRadar test suite."""

from __future__ import annotations

import pytest
from fastapi import FastAPI

from tests.apps import build_secure_app, build_vulnerable_app


@pytest.fixture
def vuln_app() -> FastAPI:
    return build_vulnerable_app()


@pytest.fixture
def secure_app() -> FastAPI:
    return build_secure_app()
