# Usage

> **Authorized use only.** Only scan systems you own or are explicitly permitted
> to test.

## CLI

```
authradar <command> [options]
```

Commands: `scan`, `list-scanners`, `serve`, `version`.

### `authradar scan <target>`

| Option | Default | Description |
| --- | --- | --- |
| `--format {json,markdown,html}` | `markdown` | Report format. |
| `-o, --output FILE` | stdout | Write the report to a file. |
| `--max-pages N` | 50 | Maximum pages to crawl. |
| `--max-depth N` | 3 | Maximum crawl depth. |
| `--concurrency N` | 10 | Concurrent in-flight requests. |
| `--timeout SECONDS` | 15 | Per-request timeout. |
| `--probe-attempts N` | 12 | Attempts used by active probes. |
| `--active` | off | Enable active probes (rate-limit, OTP, enumeration, MFA). |
| `--browser` | off | Use Playwright to inspect `localStorage`/`sessionStorage`. |
| `--insecure` | off | Disable TLS certificate verification. |
| `--allow-host HOST` | — | Additional in-scope host (repeatable). |
| `--enable ID` | — | Only run these scanner ids (repeatable). |
| `--disable ID` | — | Skip these scanner ids (repeatable). |
| `--username NAME` | — | Identifier of an account you are authorized to test. |
| `--password PW` | — | Password (or set `AUTHRADAR_PASSWORD`). |
| `--login-path PATH` | — | Login endpoint path. |
| `--logout-path PATH` | — | Logout endpoint path. |
| `--protected-path PATH` | — | A path that requires authentication. |
| `--username-field NAME` | `username` | Login form username field name. |
| `--password-field NAME` | `password` | Login form password field name. |
| `--fail-on {none,info,low,medium,high,critical}` | `high` | Exit non-zero if a finding at/above this severity is found. |
| `-q, --quiet` | off | Suppress the stderr summary. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No findings at/above the `--fail-on` threshold. |
| `1` | One or more findings at/above the threshold. |
| `2` | Configuration or scan error. |

## Passive vs active

By default a scan is **passive**: it crawls, parses, and inspects responses,
cookies, and tokens, but does not send extra traffic. Active checks
(`AR-RATE-001`, `AR-OTP-002`, `AR-ENUM-001`, `AR-MFA-001/002`, and the stateful
session checks) only run with `--active` and, where noted, require credentials
and a `--protected-path`.

Active rate-limit probing deliberately uses an **invalid username** so real
accounts are not locked out.

## Examples

```bash
# CI gate: JSON report, fail on HIGH or CRITICAL
authradar scan https://example.com --format json -o report.json --fail-on high

# Full authenticated audit (authorized target you own)
export AUTHRADAR_PASSWORD='...'
authradar scan https://example.com --active \
  --username alice --protected-path /account --logout-path /logout

# Only run JWT and cookie checks
authradar scan https://example.com --enable jwt_analyzer --enable session_checker

# Self-contained HTML report
authradar scan https://example.com --format html -o report.html
```

## HTTP API

```bash
export AUTHRADAR_API_KEY='a-long-random-secret'
authradar serve --host 127.0.0.1 --port 8000
```

- `GET /health` → `{"status": "ok", ...}`
- `POST /scan` with header `X-API-Key: <secret>` and a JSON `ScanConfig` body.

Without `AUTHRADAR_API_KEY` set, `/scan` returns `503` — scanning is disabled by
default so an exposed instance cannot be abused as an open scanning proxy.
