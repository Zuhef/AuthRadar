"""Scanner plugin contract: context, base class, and registry.

Every scanner is a :class:`BaseScanner` subclass registered via
:func:`register_scanner`. Scanners receive a :class:`ScanContext` containing all
data already collected (responses, parsed pages, detected auth flows, optional
browser storage) plus the live :class:`RequestEngine` for active probing.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar

from authradar.core.auth_flow_detector import AuthFlow, AuthFlowType
from authradar.core.config import ScanConfig
from authradar.core.exceptions import PluginError
from authradar.core.http import CapturedResponse, ParsedCookie
from authradar.core.models import Category, Finding
from authradar.core.parsing import HtmlForm, ParsedPage
from authradar.core.request_engine import RequestEngine


@dataclass(slots=True)
class BrowserStorage:
    """A snapshot of client-side storage captured from a real browser page."""

    url: str
    local_storage: dict[str, str] = field(default_factory=dict)
    session_storage: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class ScanContext:
    """Everything a scanner needs to do its work.

    Collection is performed once up-front; scanners read from these fields and
    may use :attr:`engine` for additional in-scope active probes.
    """

    config: ScanConfig
    engine: RequestEngine
    responses: list[CapturedResponse] = field(default_factory=list)
    parsed_pages: list[ParsedPage] = field(default_factory=list)
    auth_flows: list[AuthFlow] = field(default_factory=list)
    storage: list[BrowserStorage] = field(default_factory=list)

    def flows_of(self, *types: AuthFlowType) -> list[AuthFlow]:
        """Return detected flows matching any of ``types``."""
        wanted = set(types)
        return [flow for flow in self.auth_flows if flow.type in wanted]

    def forms(self) -> list[HtmlForm]:
        """All forms discovered across parsed pages."""
        return [form for page in self.parsed_pages for form in page.forms]

    def set_cookies(self) -> list[ParsedCookie]:
        """All cookies set across every captured response."""
        return [cookie for response in self.responses for cookie in response.cookies]

    @property
    def is_https_target(self) -> bool:
        """Whether the target is served over TLS."""
        return self.config.target_scheme == "https"


class BaseScanner(ABC):
    """Abstract base class for all scanners.

    Subclasses must set the ``id``, ``name`` and ``category`` class attributes
    and implement :meth:`scan`.
    """

    id: ClassVar[str] = ""
    name: ClassVar[str] = ""
    category: ClassVar[Category]
    description: ClassVar[str] = ""

    @abstractmethod
    async def scan(self, context: ScanContext) -> list[Finding]:
        """Analyse ``context`` and return any findings (possibly empty)."""
        raise NotImplementedError


_REGISTRY: dict[str, type[BaseScanner]] = {}


def register_scanner(scanner_cls: type[BaseScanner]) -> type[BaseScanner]:
    """Class decorator that registers a scanner by its ``id``.

    Raises :class:`PluginError` if the id is missing or already registered.
    """
    scanner_id = getattr(scanner_cls, "id", "")
    if not scanner_id:
        msg = f"scanner {scanner_cls.__name__} must define a non-empty 'id'"
        raise PluginError(msg)
    if not getattr(scanner_cls, "name", ""):
        msg = f"scanner {scanner_cls.__name__} must define a non-empty 'name'"
        raise PluginError(msg)
    if not hasattr(scanner_cls, "category"):
        msg = f"scanner {scanner_cls.__name__} must define a 'category'"
        raise PluginError(msg)
    existing = _REGISTRY.get(scanner_id)
    if existing is not None and existing is not scanner_cls:
        msg = f"duplicate scanner id {scanner_id!r} ({scanner_cls.__name__} vs {existing.__name__})"
        raise PluginError(msg)
    _REGISTRY[scanner_id] = scanner_cls
    return scanner_cls


def registered_scanners() -> dict[str, type[BaseScanner]]:
    """Return a copy of the scanner registry keyed by id."""
    return dict(_REGISTRY)


def clear_registry() -> None:
    """Clear the registry. Intended for tests and re-loading."""
    _REGISTRY.clear()
