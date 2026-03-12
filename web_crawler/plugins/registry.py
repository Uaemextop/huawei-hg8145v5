"""
Central plugin registry with auto-discovery.

Plugins are organized into categories:

* **detector**   – technology / WAF / protection detection
* **strategy**   – crawling and scraping strategies
* **extractor**  – link and content extraction
* **processor**  – data processing and transformation
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

log = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────
# Plugin base classes
# ────────────────────────────────────────────────────────────────────

@runtime_checkable
class Plugin(Protocol):
    """Minimal interface every plugin must satisfy."""

    @property
    def name(self) -> str: ...

    def run(self, context: dict[str, Any]) -> Any: ...


class BasePlugin(ABC):
    """Convenience base class for plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique plugin name."""

    @abstractmethod
    def run(self, context: dict[str, Any]) -> Any:
        """Execute the plugin logic.

        *context* carries request/response data whose schema depends on
        the plugin category.
        """


# ────────────────────────────────────────────────────────────────────
# Registry
# ────────────────────────────────────────────────────────────────────

VALID_CATEGORIES = frozenset({"detector", "strategy", "extractor", "processor"})


@dataclass
class PluginRegistry:
    """Thread-safe registry that holds categorised plugins."""

    _plugins: Dict[str, Dict[str, Plugin]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        for cat in VALID_CATEGORIES:
            self._plugins.setdefault(cat, {})

    # ── registration ────────────────────────────────────────────────

    def register(self, category: str, plugin: Plugin) -> None:
        """Register *plugin* under *category*."""
        if category not in VALID_CATEGORIES:
            raise ValueError(
                f"Unknown category {category!r}. "
                f"Must be one of {sorted(VALID_CATEGORIES)}"
            )
        with self._lock:
            self._plugins[category][plugin.name] = plugin
        log.debug("Registered plugin %s/%s", category, plugin.name)

    def register_detector(self, plugin: Plugin) -> None:
        self.register("detector", plugin)

    def register_strategy(self, plugin: Plugin) -> None:
        self.register("strategy", plugin)

    def register_extractor(self, plugin: Plugin) -> None:
        self.register("extractor", plugin)

    def register_processor(self, plugin: Plugin) -> None:
        self.register("processor", plugin)

    # ── lookup ──────────────────────────────────────────────────────

    def get_plugins(self, category: str) -> List[Plugin]:
        """Return all plugins in *category*."""
        return list(self._plugins.get(category, {}).values())

    def get_plugin(self, category: str, name: str) -> Optional[Plugin]:
        """Return a single plugin by *category* and *name*."""
        return self._plugins.get(category, {}).get(name)

    # ── auto-discovery ──────────────────────────────────────────────

    def discover(self, package_name: str = "web_crawler.plugins") -> None:
        """Walk *package_name* and call each module's ``register`` function."""
        try:
            pkg = importlib.import_module(package_name)
        except ImportError:
            log.warning("Plugin package %s not found", package_name)
            return

        prefix = pkg.__name__ + "."
        path = getattr(pkg, "__path__", None)
        if path is None:
            return

        for importer, modname, ispkg in pkgutil.walk_packages(path, prefix):
            try:
                mod = importlib.import_module(modname)
            except Exception:
                log.warning("Failed to import plugin module %s", modname, exc_info=True)
                continue
            register_fn = getattr(mod, "register", None)
            if callable(register_fn):
                try:
                    register_fn(self)
                except Exception:
                    log.warning(
                        "Plugin %s register() failed", modname, exc_info=True
                    )
