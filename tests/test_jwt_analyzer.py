"""Tests for authradar.scanner.jwt_analyzer."""

from __future__ import annotations

import base64
import json
from typing import Any

from authradar.core.scanner_base import BrowserStorage
from authradar.scanner.heuristics import find_jwts
from authradar.scanner.jwt_analyzer import (
    analyze_jwt_claims,
    analyze_token_storage,
    analyze_url_for_jwt,
    decode_jwt,
)


def _b64(data: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def _jwt(header: dict[str, Any], payload: dict[str, Any], signature: str = "sig") -> str:
    return f"{_b64(header)}.{_b64(payload)}.{signature}"


def test_decode_valid_and_invalid() -> None:
    token = _jwt({"alg": "HS256"}, {"sub": "1"})
    decoded = decode_jwt(token)
    assert decoded is not None
    assert decoded.alg == "HS256"
    assert decoded.payload["sub"] == "1"
    assert decode_jwt("not.a.jwt.token") is None
    assert decode_jwt("only.two") is None
    assert decode_jwt("@@@.@@@.@@@") is None


def test_alg_none_is_critical() -> None:
    decoded = decode_jwt(_jwt({"alg": "none"}, {"sub": "1", "exp": 9999999999}))
    assert decoded is not None
    ids = {f.id for f in analyze_jwt_claims(decoded, location="cookie")}
    assert "AR-JWT-001" in ids


def test_missing_exp_flagged() -> None:
    decoded = decode_jwt(_jwt({"alg": "HS256"}, {"sub": "1"}))
    assert decoded is not None
    ids = {f.id for f in analyze_jwt_claims(decoded, location=None)}
    assert "AR-JWT-002" in ids


def test_long_lived_flagged() -> None:
    decoded = decode_jwt(_jwt({"alg": "HS256"}, {"iat": 0, "exp": 200_000}))
    assert decoded is not None
    ids = {f.id for f in analyze_jwt_claims(decoded, location=None, now=0.0)}
    assert "AR-JWT-003" in ids
    assert "AR-JWT-002" not in ids


def test_sensitive_claim_flagged() -> None:
    decoded = decode_jwt(_jwt({"alg": "HS256"}, {"exp": 9999999999, "password": "secret"}))
    assert decoded is not None
    ids = {f.id for f in analyze_jwt_claims(decoded, location=None)}
    assert "AR-JWT-004" in ids


def test_short_lived_token_clean() -> None:
    decoded = decode_jwt(_jwt({"alg": "RS256"}, {"iat": 0, "exp": 600}))
    assert decoded is not None
    assert analyze_jwt_claims(decoded, location=None, now=0.0) == []


def test_storage_local_and_session() -> None:
    token = _jwt({"alg": "HS256"}, {"sub": "1", "exp": 9999999999})
    storage = BrowserStorage(
        url="http://t/app",
        local_storage={"jwt": token},
        session_storage={"access_token": "opaque-value"},
    )
    findings = analyze_token_storage(storage)
    ids = {f.id for f in findings}
    assert "AR-JWT-005" in ids  # localStorage
    assert "AR-JWT-006" in ids  # sessionStorage (auth-token key)


def test_url_leak() -> None:
    token = _jwt({"alg": "HS256"}, {"sub": "1"})
    findings = analyze_url_for_jwt(f"http://t/cb?token={token}")
    assert [f.id for f in findings] == ["AR-JWT-007"]
    assert analyze_url_for_jwt("http://t/clean?x=1") == []


def test_find_jwts_dedupes() -> None:
    token = _jwt({"alg": "HS256"}, {"sub": "1"})
    assert find_jwts(f"{token} and again {token}") == [token]
    assert find_jwts("nothing here") == []
