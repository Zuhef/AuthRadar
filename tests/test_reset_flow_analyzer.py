"""Tests for authradar.scanner.reset_flow_analyzer."""

from __future__ import annotations

from authradar.scanner.reset_flow_analyzer import (
    analyze_reset_token,
    analyze_token_lifetime,
    analyze_token_replay,
    analyze_token_sequence,
    estimate_token_entropy_bits,
    extract_reset_tokens,
)


def test_weak_numeric_token() -> None:
    finding = analyze_reset_token("123456")
    assert finding is not None
    assert finding.id == "AR-RESET-001"


def test_strong_token_clean() -> None:
    assert analyze_reset_token("f3A9c1B7d2E5f8A0c4B6d9E1f2A3c5B7") is None


def test_low_diversity_token_flagged() -> None:
    assert analyze_reset_token("aaaaaaaaaaaaaaaa") is not None


def test_entropy_estimate_orders_tokens() -> None:
    assert estimate_token_entropy_bits("123456") < estimate_token_entropy_bits("aB3xK9mZq2WpL7rT")


def test_sequential_tokens_flagged() -> None:
    finding = analyze_token_sequence(["1001", "1002", "1003"])
    assert finding is not None
    assert finding.id == "AR-RESET-004"


def test_non_sequential_tokens_clean() -> None:
    assert analyze_token_sequence(["839201", "118277"]) is None
    assert analyze_token_sequence(["only-one"]) is None


def test_token_replay() -> None:
    replay = analyze_token_replay(first_use_accepted=True, second_use_accepted=True)
    assert replay is not None
    assert replay.id == "AR-RESET-002"
    assert analyze_token_replay(first_use_accepted=True, second_use_accepted=False) is None


def test_token_lifetime() -> None:
    long_lived = analyze_token_lifetime(7200)
    assert long_lived is not None
    assert long_lived.id == "AR-RESET-003"
    assert analyze_token_lifetime(600) is None


def test_extract_reset_tokens() -> None:
    tokens = extract_reset_tokens("http://t/reset-password?token=abcdefgh12345678")
    assert "abcdefgh12345678" in tokens
    assert extract_reset_tokens("http://t/home?ref=12345678") == []
