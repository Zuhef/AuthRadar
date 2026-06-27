# Developer guide

This guide goes deeper than [`CONTRIBUTING.md`](../CONTRIBUTING.md). Read
[`architecture.md`](architecture.md) first for the high-level design.

## Project layout

```
authradar/
  core/        models, config, http capture, request engine, parsing,
               crawler, endpoint discovery, auth-flow detection,
               scanner base/registry, plugin loader, optional browser capture
  scanner/     one module per detection family + shared heuristics
  reporting/   base reporter + json/markdown/html
  cli/         argparse parser (main.py) and command implementations (commands.py)
  api.py       optional FastAPI server
  engine.py    run_scan() orchestrator
tests/         pure-function tests, in-process ASGI integration, adversarial
docs/          architecture, checks, usage, development, writing-plugins
```

## The golden rule: collection vs analysis

Anything that performs I/O (network or browser) is **collection**. Anything that
decides whether something is a finding is **analysis**, and analysis must be a
**pure function**:

```python
# pure analysis -> trivially unit-testable, no network
def analyze_cookie_security(cookies, *, is_https) -> list[Finding]: ...

# collection -> lives in the scanner's async scan()
class SessionCheckerScanner(BaseScanner):
    async def scan(self, context) -> list[Finding]:
        return analyze_cookie_security(context.set_cookies(),
                                       is_https=context.is_https_target)
```

If you find yourself wanting the network inside a detection rule, split it: have
the `scan()` method collect the data, then pass it to a pure function.

## Testing philosophy

Three layers, all run by `pytest`:

1. **Pure-function tests** — feed synthetic inputs to the analysis functions and
   assert on the `Finding` ids/severities. Fast, deterministic, no network.
2. **Integration tests** — drive scanners and `run_scan()` against in-process
   FastAPI apps using `httpx.ASGITransport` (see `tests/apps.py` for a
   deliberately-vulnerable app and a secure one, and `tests/helpers.py` for the
   `engine_for(app)` helper). No real network or browser is used.
3. **Adversarial tests** (`tests/test_adversarial.py`) — feed malformed/hostile
   HTML, JWTs, cookies, and redirects to the trust boundaries and assert nothing
   crashes.

`pytest` is configured with `asyncio_mode = "auto"` (async tests need no
decorator) and `filterwarnings = ["error::DeprecationWarning"]` (deprecations
fail the build).

## Walkthrough: adding a check end to end

Suppose you want to flag a login form whose password field allows autocomplete.

1. **Pure function** in `authradar/scanner/login_detector.py`:

   ```python
   def analyze_password_autocomplete(form: HtmlForm) -> Finding | None:
       pw = form.input_by_type("password")
       if pw is not None and (pw.autocomplete or "").lower() == "on":
           return Finding(id="AR-LOGIN-003", severity=Severity.LOW, ...)
       return None
   ```

2. **Wire it** into the scanner's `scan()` loop over `context.flows_of(...)`.
3. **Test** the pure function in `tests/test_login_detector.py` (both the
   positive and negative case).
4. **Document** `AR-LOGIN-003` in [`checks.md`](checks.md) and the README table.
5. **Changelog** entry under "Unreleased".

## Running things locally

```bash
# the whole gate
ruff check . && ruff format --check . && mypy authradar tests && pytest -q \
  && bandit -r authradar -c pyproject.toml && pip-audit -r requirements.txt

# a single test file / test
pytest tests/test_jwt_analyzer.py -q
pytest tests/test_session_checker.py::test_session_fixation -q

# try the CLI from source
python -m authradar scan https://example.com          # or: authradar scan ...
```

## Debugging tips

- Scanners are isolated by the engine: an exception in one scanner is captured
  into `ScanResult.errors` rather than aborting the run. When developing, run the
  scanner directly (`await MyScanner().scan(context)`) to see the traceback.
- The request engine raises `ScopeError` for out-of-scope URLs and
  `RequestEngineError` (wrapping transport failures) — catch `AuthRadarError` to
  handle both.
- Cookies are sent explicitly per request via a `Cookie` header; the engine
  disables httpx's implicit cookie jar so probes have isolated session state.

## Type checking & style

- `mypy --strict` over `authradar` and `tests`. Keep everything typed; prefer
  immutable pydantic models (`frozen=True`) and `StrEnum` for string enums.
- `ruff` enforces lint and formatting (line length 100). Run `ruff format .`.
