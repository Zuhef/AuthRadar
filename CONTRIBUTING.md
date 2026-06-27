# Contributing to AuthRadar

Thanks for your interest in improving AuthRadar! Contributions of all kinds are
welcome: bug reports, new checks, documentation, and reviews.

By participating in this project you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md). Please also read [`SECURITY.md`](SECURITY.md)
— AuthRadar is a **defensive** tool and there are limits on what we will accept.

## Table of contents

- [Ways to contribute](#ways-to-contribute)
- [Reporting issues](#reporting-issues)
- [Development setup](#development-setup)
- [Quality gates](#quality-gates)
- [Design principles](#design-principles)
- [Adding a scanner / check](#adding-a-scanner--check)
- [Coding standards](#coding-standards)
- [Commit & branch conventions](#commit--branch-conventions)
- [Pull request checklist](#pull-request-checklist)
- [Versioning & releases](#versioning--releases)
- [Responsible use](#responsible-use)

## Ways to contribute

- **Report a bug** or a false positive/negative in a check.
- **Propose a new check** for an authentication weakness we don't yet cover.
- **Improve detection accuracy** of an existing scanner.
- **Improve docs** — the README, `docs/`, or inline docstrings.
- **Review open pull requests.**

## Reporting issues

Open an issue using one of the templates:

- **Bug report** — something is broken or a check is wrong.
- **Feature request** — a new capability or option.
- **New scanner / check** — propose a detection for an auth weakness.

Do **not** open a public issue for a vulnerability *in AuthRadar itself* — follow
the private process in [`SECURITY.md`](SECURITY.md).

## Development setup

Requires Python 3.12+.

```bash
git clone https://github.com/authradar/authradar
cd authradar
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
playwright install chromium        # optional, only for browser-based checks
```

## Quality gates

Every change must pass the full pipeline before it is merged. CI runs exactly
these commands on Python 3.12 and 3.13:

```bash
ruff check .                                  # lint
ruff format --check .                          # formatting
mypy authradar tests                           # strict type checking
pytest                                         # unit + integration tests
bandit -r authradar -c pyproject.toml          # security static analysis
pip-audit -r requirements.txt                  # dependency vulnerabilities
```

Run `ruff format .` to auto-format your changes. A convenient one-liner to run
everything locally:

```bash
ruff check . && ruff format --check . && mypy authradar tests && pytest -q \
  && bandit -r authradar -c pyproject.toml && pip-audit -r requirements.txt
```

## Design principles

- **Separate I/O from analysis.** Collection (network/browser) lives in the
  request engine, crawler, and scanner `scan()` methods. Detection logic must be
  **pure functions** that take captured data and return `Finding` objects, so it
  can be unit-tested deterministically without the network.
- **Secure by default.** Active probing is opt-in. Requests are confined to the
  target host. Never weaken these defaults.
- **Full type hints.** The package is checked with `mypy --strict`.
- **No placeholder code.** No TODOs, no stubs, no silently-swallowed exceptions.

See [`docs/architecture.md`](docs/architecture.md) for the full picture and
[`docs/development.md`](docs/development.md) for a deeper developer guide.

## Adding a scanner / check

1. Create a module in `authradar/scanner/`.
2. Write the detection logic as **pure functions** (these are what you unit-test).
3. Add a `BaseScanner` subclass decorated with `@register_scanner`, setting the
   `id`, `name`, and `category` class variables.
4. Import the module in `authradar/scanner/__init__.py`.
5. Add tests in `tests/` — pure-function tests plus, where relevant, an
   integration test against an in-process app (see `tests/apps.py`).
6. Document the new check IDs in [`docs/checks.md`](docs/checks.md) and the
   README's "What it detects" table.

Each check needs a stable `AR-...` id, a severity, a confidence, a CWE reference,
and clear remediation guidance.

Third-party scanners can be shipped as separate packages via the
`authradar.scanners` entry-point group — see
[`docs/writing-plugins.md`](docs/writing-plugins.md).

## Coding standards

- Target Python 3.12+; use modern typing (`X | None`, `list[...]`, `StrEnum`).
- Keep public functions and models fully typed; prefer immutable models
  (`frozen=True`) for data that crosses module boundaries.
- Treat all data from the target (HTML, headers, cookies, JWTs) as **untrusted**:
  parse defensively and never raise on malformed input.
- Line length is 100; formatting and import order are enforced by `ruff`.

## Commit & branch conventions

- Branch from `main`, e.g. `feature/oauth-state-check` or `fix/cookie-parsing`.
- Use clear, imperative commit messages. [Conventional Commits](https://www.conventionalcommits.org/)
  prefixes (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`) are
  encouraged but not required.
- Keep commits focused; rebase/squash noisy WIP history before review.

## Pull request checklist

Before requesting review, confirm:

- [ ] All quality gates pass locally (lint, format, types, tests, security, audit).
- [ ] New behaviour is covered by tests (pure-function tests where applicable).
- [ ] New checks include a CWE reference and remediation text.
- [ ] Docs updated (`docs/checks.md`, README table, docstrings) if behaviour changed.
- [ ] `CHANGELOG.md` has an entry under "Unreleased".
- [ ] No secrets, real credentials, or unauthorized-target data are committed.

## Versioning & releases

AuthRadar follows [Semantic Versioning](https://semver.org/). Releases are cut by
maintainers:

1. Move the "Unreleased" notes in [`CHANGELOG.md`](CHANGELOG.md) under a new
   version heading with the date.
2. Bump the version in `pyproject.toml` and `authradar/__init__.py`
   (`__version__`).
3. Tag the commit `vX.Y.Z` and push; CI builds and validates the package and the
   Docker image.

## Responsible use

AuthRadar is a defensive auditing tool. Contributions that turn it into a generic
attack/exploitation tool (credential stuffing, account-takeover automation,
mass scanning of third parties, etc.) are out of scope and will be declined. See
[`SECURITY.md`](SECURITY.md).
