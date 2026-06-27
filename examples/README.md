# Examples

> Authorized use only — scan systems you own or are permitted to test.

## `programmatic_scan.py`

Run a passive scan from Python and print a Markdown report:

```bash
python examples/programmatic_scan.py https://example.com
```

Exits non-zero if any finding is reported.

## CLI recipes

```bash
# CI gate (JSON, fail on HIGH+)
authradar scan https://example.com --format json -o report.json --fail-on high

# Authenticated active audit
export AUTHRADAR_PASSWORD='...'
authradar scan https://example.com --active \
  --username alice --protected-path /account --logout-path /logout
```
