"""Base handler interface for technology-specific crawling corrections."""
from __future__ import annotations

import abc
import logging
from typing import TYPE_CHECKING, TypedDict

if TYPE_CHECKING:
    import requests

log = logging.getLogger(__name__)

__all__ = ["BaseHandler", "HandlerResult"]


class HandlerResult(TypedDict, total=False):
    """Structured result returned by every handler."""

    handler: str  # Handler name
    actions_taken: list[str]  # Description of actions performed
    extra_urls: list[str]  # Additional URLs to crawl
    extra_headers: dict  # Headers to add to future requests
    recommended_config: dict  # Config suggestions (e.g., use_browser: True)
    skip_page: bool  # Whether to skip saving this page
    retry_with: dict  # Retry config (new headers, cookies, etc.)


class BaseHandler(abc.ABC):
    """Abstract base class for all technology-specific handlers.

    Each concrete handler targets one or more detection types and applies
    crawling corrections (extra URLs to discover, headers to inject,
    recommended config changes, etc.).
    """

    name: str = ""

    @abc.abstractmethod
    def can_handle(self, detection: dict) -> bool:
        """Return True if this handler can process the given detection."""

    @abc.abstractmethod
    def apply(
        self,
        url: str,
        session: "requests.Session",
        response: "requests.Response | None",
        detection: dict,
    ) -> HandlerResult:
        """Apply correction strategy. Returns HandlerResult with actions."""
