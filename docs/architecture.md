# Architecture

AuthRadar is built around one core idea: **separate I/O (collection) from pure
analysis (detection)**. Everything that touches the network or a browser is
isolated, and every detection rule is a pure, deterministic function that takes
captured data and returns `Finding` objects. This makes the security-relevant
logic exhaustively unit-testable without a live target.

## Data flow

```
ScanConfig
   │
   ▼
RequestEngine ──► crawl() ──► endpoint discovery ──► detect_auth_flows()
   │                                                        │
   │  (optional) browser storage capture                    │
   ▼                                                        ▼
                         ScanContext  (config, engine, responses,
                                       parsed_pages, auth_flows, storage)
                                          │
                                          ▼
                       selected scanners run concurrently (isolated)
                                          │
                                          ▼
                          de-duplicated Finding list
                                          │
                                          ▼
                              ScanResult ──► reporters (json/md/html)
```

## Components

### `core/`

- **`models.py`** — immutable result types: `Severity`, `Confidence`,
  `Category`, `Finding` (frozen, hashable), `ScanResult`.
- **`config.py`** — `ScanConfig`/`AuthConfig` with validation and secure
  defaults (TLS verification on, active probes off, crawl bounded).
- **`http.py`** — `CapturedResponse`/`CapturedRequest` and robust `Set-Cookie`
  parsing. All parsing treats input as untrusted and never raises.
- **`request_engine.py`** — the only component that performs network I/O. It
  enforces a host allowlist on every redirect hop (defence against
  scope-escape/SSRF), bounds concurrency with a semaphore, disables implicit
  cookie persistence (cookies are passed explicitly per request), and redacts
  sensitive request headers in captured snapshots.
- **`parsing.py`** — pure HTML extraction (forms, links, scripts, meta) using
  BeautifulSoup with the stdlib parser.
- **`auth_flow_detector.py`** — heuristic classification of forms/links into
  authentication flow types.
- **`crawler.py` / `endpoint_discovery.py`** — async breadth-first crawl plus
  probing of common authentication paths.
- **`scanner_base.py`** — the `ScanContext`, the `BaseScanner` ABC, and the
  scanner registry.
- **`plugin_loader.py`** — loads built-in scanners and third-party scanners via
  the `authradar.scanners` entry-point group.

### `scanner/`

One module per detection family. Each module exposes **pure analysis functions**
(the tested core) and a thin `BaseScanner` subclass that performs collection and
delegates to those functions.

### `reporting/`

`JsonReporter`, `MarkdownReporter`, `HtmlReporter`. The HTML reporter escapes all
dynamic content because some of it (URLs, cookie names) originates in the scanned
application and is therefore untrusted.

### `engine.py`

Orchestrates a scan: collect → build `ScanContext` → run scanners concurrently
(each isolated so one failure cannot abort the run) → de-duplicate findings by
fingerprint → assemble `ScanResult`.

### `api.py` / `cli/`

An optional FastAPI server (secure by default — `/scan` requires an API key) and
an `argparse`-based command-line interface.

## Trust boundaries

Everything coming back from the target — HTML, headers, `Set-Cookie`, JWTs,
JSON — is **untrusted input**. Parsers are defensive and never raise on
malformed data; the HTML reporter escapes target-derived strings; the request
engine refuses to leave the authorized host.
