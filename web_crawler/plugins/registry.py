"""
Auto-loading plugin registry.

Discovers all :class:`CrawlerPlugin` subclasses in the ``plugins``
package and provides ordered access for the crawler engine.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Any, Iterable

from web_crawler.plugins.base import CrawlerPlugin
from web_crawler.utils.log import log


class PluginRegistry:
    """Maintains an ordered collection of active plugins."""

    def __init__(self) -> None:
        self._plugins: list[CrawlerPlugin] = []

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, plugin: CrawlerPlugin) -> None:
        """Manually register a plugin instance."""
        self._plugins.append(plugin)
        self._plugins.sort(key=lambda p: p.priority)
        log.debug("[PLUGINS] Registered plugin: %s (priority=%d)",
                  plugin.name, plugin.priority)

    def auto_discover(self) -> None:
        """Walk the ``web_crawler.plugins`` package and instantiate every
        concrete :class:`CrawlerPlugin` subclass found.

        Only subclasses defined inside the package are loaded; the base
        class itself is skipped.
        """
        import web_crawler.plugins as _pkg

        for _importer, mod_name, _ispkg in pkgutil.walk_packages(
            _pkg.__path__, prefix=_pkg.__name__ + ".",
        ):
            # Skip the base / registry modules themselves
            if mod_name.endswith((".base", ".registry")):
                continue
            try:
                module = importlib.import_module(mod_name)
            except Exception as exc:          # noqa: BLE001
                log.debug("[PLUGINS] Could not import %s: %s", mod_name, exc)
                continue

            for attr_name in dir(module):
                obj = getattr(module, attr_name)
                if (
                    isinstance(obj, type)
                    and issubclass(obj, CrawlerPlugin)
                    and obj is not CrawlerPlugin
                    and not getattr(obj, "_abstract", False)
                ):
                    try:
                        instance = obj()
                        self.register(instance)
                    except Exception as exc:  # noqa: BLE001
                        log.debug("[PLUGINS] Could not instantiate %s: %s",
                                  attr_name, exc)

    # ------------------------------------------------------------------
    # Access
    # ------------------------------------------------------------------

    @property
    def plugins(self) -> list[CrawlerPlugin]:
        return list(self._plugins)

    def get(self, name: str) -> CrawlerPlugin | None:
        """Return the first plugin whose *name* matches."""
        for p in self._plugins:
            if p.name == name:
                return p
        return None

    # ------------------------------------------------------------------
    # Bulk hook invocation helpers
    # ------------------------------------------------------------------

    def call_hook(self, hook_name: str, *args: Any, **kwargs: Any) -> list[Any]:
        """Call *hook_name* on every registered plugin, collecting results."""
        results: list[Any] = []
        for plugin in self._plugins:
            method = getattr(plugin, hook_name, None)
            if method is not None:
                try:
                    results.append(method(*args, **kwargs))
                except Exception as exc:  # noqa: BLE001
                    log.debug("[PLUGINS] %s.%s error: %s",
                              plugin.name, hook_name, exc)
        return results

    def detect_technologies(
        self,
        url: str,
        headers: dict[str, str],
        body: str,
    ) -> list[str]:
        """Aggregate technology detections across all plugins."""
        techs: list[str] = []
        for plugin in self._plugins:
            techs.extend(plugin.detect_technology(url, headers, body))
        return techs

    def detect_protections(
        self,
        url: str,
        headers: dict[str, str],
        body: str,
    ) -> list[str]:
        """Aggregate protection/WAF detections across all plugins."""
        protections: list[str] = []
        for plugin in self._plugins:
            protections.extend(plugin.detect_protection(url, headers, body))
        return protections

    def collect_extra_links(
        self,
        url: str,
        body: str,
        content_type: str,
    ) -> set[str]:
        """Collect all extra links found by plugins."""
        links: set[str] = set()
        for plugin in self._plugins:
            links.update(plugin.extract_links(url, body, content_type))
        return links
