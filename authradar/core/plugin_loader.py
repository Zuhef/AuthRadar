"""Plugin loading and scanner selection.

Built-in scanners register themselves when :mod:`authradar.scanner` is
imported. Third-party scanners may be distributed as packages exposing the
``authradar.scanners`` entry-point group; each entry point must resolve to a
:class:`BaseScanner` subclass.
"""

from __future__ import annotations

from importlib import import_module
from importlib.metadata import entry_points

from authradar.core.config import ScanConfig
from authradar.core.exceptions import ConfigError, PluginError
from authradar.core.scanner_base import BaseScanner, register_scanner, registered_scanners

ENTRY_POINT_GROUP = "authradar.scanners"
_BUILTIN_PACKAGE = "authradar.scanner"


def load_builtin_scanners() -> None:
    """Import the built-in scanner package, triggering registration."""
    import_module(_BUILTIN_PACKAGE)


def load_plugin_scanners() -> list[str]:
    """Load and register third-party scanners declared via entry points.

    Returns the names of loaded entry points. Raises :class:`PluginError` if an
    entry point fails to import or does not resolve to a scanner class.
    """
    loaded: list[str] = []
    for entry_point in entry_points(group=ENTRY_POINT_GROUP):
        try:
            obj = entry_point.load()
        except Exception as exc:
            msg = f"failed to load scanner plugin {entry_point.name!r}: {exc}"
            raise PluginError(msg) from exc
        if not (isinstance(obj, type) and issubclass(obj, BaseScanner)):
            msg = f"plugin {entry_point.name!r} does not resolve to a BaseScanner subclass"
            raise PluginError(msg)
        register_scanner(obj)
        loaded.append(entry_point.name)
    return loaded


def select_scanners(config: ScanConfig) -> list[BaseScanner]:
    """Instantiate the scanners enabled by ``config``, sorted by id.

    Raises :class:`ConfigError` if ``enabled_scanners`` names an unknown id.
    """
    load_builtin_scanners()
    load_plugin_scanners()

    registry = registered_scanners()
    available = set(registry)

    selected = set(available)
    if config.enabled_scanners is not None:
        requested = set(config.enabled_scanners)
        unknown = requested - available
        if unknown:
            msg = f"unknown scanners requested: {sorted(unknown)}"
            raise ConfigError(msg)
        selected &= requested

    selected -= set(config.disabled_scanners)

    return [registry[scanner_id]() for scanner_id in sorted(selected)]
