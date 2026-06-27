"""AuthRadar — an asynchronous authentication security auditing framework.

AuthRadar audits the authentication surface of web applications you are
authorized to test. It crawls a target, discovers authentication-related
endpoints, and runs a suite of modular scanners that detect common
authentication and session-management weaknesses.

The public API intentionally stays small; import from the submodules
(:mod:`authradar.core`, :mod:`authradar.scanner`, :mod:`authradar.reporting`)
for the building blocks.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
