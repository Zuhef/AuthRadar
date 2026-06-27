<!-- Thanks for contributing to AuthRadar! Please fill out the sections below. -->

## Summary

<!-- What does this PR change, and why? -->

## Type of change

- [ ] Bug fix
- [ ] New check / scanner
- [ ] Improvement to an existing check
- [ ] Documentation
- [ ] Tooling / CI
- [ ] Other (describe):

## How was this tested?

<!-- Commands you ran and their results. Include new tests you added. -->

## Checklist

- [ ] Quality gates pass locally: `ruff check .`, `ruff format --check .`,
      `mypy authradar tests`, `pytest`, `bandit -r authradar -c pyproject.toml`,
      `pip-audit -r requirements.txt`
- [ ] New behaviour is covered by tests (pure-function tests where applicable)
- [ ] New checks include a CWE reference and remediation guidance
- [ ] Docs updated (`docs/checks.md`, README table, docstrings) where relevant
- [ ] `CHANGELOG.md` updated under "Unreleased"
- [ ] No secrets, real credentials, or unauthorized-target data committed
- [ ] Change stays within AuthRadar's defensive scope (see `SECURITY.md`)
