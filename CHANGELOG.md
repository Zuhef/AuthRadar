# Changelog

All notable changes to AuthRadar are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Nothing yet._

## [0.1.0] - 2026-06-27

Initial release.

### Added

- **Async core**: host-scoped `RequestEngine` (re-checks scope on every redirect
  hop to prevent scope-escape/SSRF, bounds concurrency, redacts sensitive
  headers), crawler, common-endpoint discovery, defensive HTML parsing, and
  heuristic authentication-flow detection.
- **Plugin architecture**: `BaseScanner` registry plus a `authradar.scanners`
  entry-point group for third-party scanners.
- **Nine built-in scanners** covering login transport, cookie flags, session
  fixation and logout invalidation, CSRF on auth forms, JWT analysis and token
  storage, login and OTP rate limiting, password-reset token weaknesses, account
  enumeration, and MFA bypass / step validation.
- **Reporting** in JSON, Markdown, and self-contained HTML (with output escaping).
- **CLI** (`scan`, `list-scanners`, `serve`, `version`) with `--fail-on`
  thresholds and CI-friendly exit codes.
- **Optional FastAPI server**, secure by default (the `/scan` endpoint is
  disabled until `AUTHRADAR_API_KEY` is set).
- **Quality tooling**: `mypy --strict`, `ruff`, `bandit`, `pip-audit`, and a
  pytest suite (unit + in-process ASGI integration + adversarial/fuzz tests).
- Documentation (`README`, `docs/`), Docker image, and GitHub Actions CI.

### Security

- Active probes are opt-in (`--active`) and the rate-limit probe uses a
  deliberately invalid username so real accounts are not locked out.

[Unreleased]: https://github.com/authradar/authradar/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/authradar/authradar/releases/tag/v0.1.0
