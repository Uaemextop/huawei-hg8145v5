"""
Abstract base class for crawler plugins.

Every plugin inherits from :class:`CrawlerPlugin` and may override any
of the hook methods.  The core crawler calls these hooks at well-defined
points in the crawling pipeline, allowing plugins to extend behaviour
without modifying the engine.
"""

from __future__ import annotations

import argparse
from abc import ABC
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import requests


class CrawlerPlugin(ABC):
    """Base class that all crawler plugins must extend.

    Subclasses override only the hooks they need.  Every hook has a
    default no-op implementation so plugins can be minimal.
    """

    # Human-readable name shown in logs and CLI help.
    name: str = "base"

    # Priority controls execution order (lower = earlier).
    priority: int = 100

    # ------------------------------------------------------------------
    # CLI integration
    # ------------------------------------------------------------------

    def register_cli_args(self, parser: argparse.ArgumentParser) -> None:
        """Add plugin-specific CLI arguments to *parser*."""

    def configure(self, args: argparse.Namespace, **kwargs: Any) -> None:
        """Called after CLI argument parsing.  The plugin can read its
        arguments from *args* and prepare any internal state."""

    # ------------------------------------------------------------------
    # Lifecycle hooks
    # ------------------------------------------------------------------

    def on_crawler_start(self, crawler: Any) -> None:
        """Called once when the crawler begins its run."""

    def on_crawler_stop(self, crawler: Any) -> None:
        """Called once when the crawler finishes."""

    # ------------------------------------------------------------------
    # Request / response hooks
    # ------------------------------------------------------------------

    def before_request(self, url: str, headers: dict[str, str]) -> dict[str, str]:
        """Modify *headers* (or the URL) before a request is sent.

        Returns the (possibly modified) headers dict.
        """
        return headers

    def after_response(
        self,
        url: str,
        response: "requests.Response",
    ) -> "requests.Response | None":
        """Inspect or transform the response.

        Return the response to continue normal processing, or ``None``
        to signal that the response has been fully handled by the plugin
        (the crawler will skip its default processing).
        """
        return response

    # ------------------------------------------------------------------
    # Detection hooks
    # ------------------------------------------------------------------

    def detect_technology(
        self,
        url: str,
        headers: dict[str, str],
        body: str,
    ) -> list[str]:
        """Return a list of technology identifiers found on the page."""
        return []

    def detect_protection(
        self,
        url: str,
        headers: dict[str, str],
        body: str,
    ) -> list[str]:
        """Return a list of protection/WAF identifiers found."""
        return []

    # ------------------------------------------------------------------
    # Extraction hooks
    # ------------------------------------------------------------------

    def extract_links(
        self,
        url: str,
        body: str,
        content_type: str,
    ) -> set[str]:
        """Return extra links discovered by this plugin."""
        return set()

    def extract_seed_urls(self) -> list[str]:
        """Return additional seed URLs for the crawler queue."""
        return []

    # ------------------------------------------------------------------
    # Pipeline stage hooks
    # ------------------------------------------------------------------

    def on_discovery(self, url: str) -> bool:
        """Called when a new URL is discovered.

        Return ``True`` to allow the URL into the queue, ``False`` to
        reject it.  The default is to accept everything.
        """
        return True

    def on_content_processed(
        self,
        url: str,
        local_path: str,
        content_type: str,
    ) -> None:
        """Called after content has been saved to disk."""
