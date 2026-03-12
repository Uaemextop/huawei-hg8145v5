"""
Plugin base class and registry.

Every plugin subclasses :class:`BasePlugin` and is automatically
registered by the :class:`_PluginMeta` metaclass.  The registry is
a simple singleton list that the pipeline queries at runtime.
"""

from __future__ import annotations

import abc
import importlib
import logging
import pkgutil
from typing import Any

log = logging.getLogger("web-crawler")


# ── Registry ───────────────────────────────────────────────────────

class PluginRegistry:
    """Central catalogue of all registered plugin instances."""

    _plugins: list["BasePlugin"] = []

    @classmethod
    def register(cls, plugin: "BasePlugin") -> None:
        cls._plugins.append(plugin)

    @classmethod
    def all(cls) -> list["BasePlugin"]:
        return list(cls._plugins)

    @classmethod
    def by_kind(cls, kind: str) -> list["BasePlugin"]:
        """Return plugins matching a specific *kind* tag."""
        return [p for p in cls._plugins if p.kind == kind]

    @classmethod
    def clear(cls) -> None:
        """Remove all registered plugins (useful for testing)."""
        cls._plugins.clear()


# ── Metaclass for auto-registration ───────────────────────────────

class _PluginMeta(abc.ABCMeta):
    """Metaclass that auto-registers non-abstract plugin sub-classes."""

    def __init__(cls, name: str, bases: tuple, namespace: dict) -> None:
        super().__init__(name, bases, namespace)
        # Only register concrete (non-abstract) sub-classes of BasePlugin
        if bases and not getattr(cls, "__abstractmethods__", frozenset()):
            try:
                instance = cls()
                PluginRegistry.register(instance)
            except TypeError:
                pass  # abstract or missing required args – skip


# ── Base class ─────────────────────────────────────────────────────

class BasePlugin(metaclass=_PluginMeta):
    """Abstract base for all plugins.

    Sub-classes must set *name* and *kind* and implement at least one
    of the hook methods.  Available *kind* values:

    * ``"tech_detector"``  – technology / framework detection
    * ``"waf_detector"``   – WAF / protection detection
    * ``"link_extractor"`` – specialised link extraction
    * ``"content_analyzer"`` – page content analysis
    * ``"endpoint_discovery"`` – hidden endpoint discovery
    """

    name: str = ""
    kind: str = ""
    priority: int = 100  # lower = runs first

    # ── Hook methods (override in sub-classes) ─────────────────────

    def detect(
        self,
        *,
        url: str,
        headers: dict[str, str],
        body: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Run detection logic and return a result dict.

        Called by the pipeline for ``tech_detector`` and ``waf_detector``
        plugins.  Return an empty dict if nothing was detected.
        """
        return {}

    def extract_links(
        self,
        *,
        url: str,
        body: str,
        base: str,
        **kwargs: Any,
    ) -> set[str]:
        """Return additional URLs found in the page.

        Called for ``link_extractor`` and ``endpoint_discovery`` plugins.
        """
        return set()

    def analyze(
        self,
        *,
        url: str,
        headers: dict[str, str],
        body: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Return analysis results for a page.

        Called for ``content_analyzer`` plugins.
        """
        return {}


# ── Dynamic loader ─────────────────────────────────────────────────

def load_plugins() -> list[BasePlugin]:
    """Import every module inside the *plugins* package so that their
    :class:`BasePlugin` subclasses get registered automatically.

    Returns the current list of registered plugins.
    """
    import web_crawler.plugins as _pkg

    for _importer, modname, _ispkg in pkgutil.iter_modules(_pkg.__path__):
        if modname == "base":
            continue
        try:
            importlib.import_module(f"web_crawler.plugins.{modname}")
        except Exception as exc:  # pragma: no cover
            log.warning("Failed to load plugin module %s: %s", modname, exc)

    return PluginRegistry.all()
