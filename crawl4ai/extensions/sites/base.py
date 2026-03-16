"""
crawl4ai.extensions.sites.base – Abstract base class for site modules.

Every site-specific module must subclass :class:`BaseSiteModule` and
implement two methods:

* :meth:`matches` – Return ``True`` if this module applies to the given URL.
* :meth:`extra_urls` – Return a set of additional download URLs discovered
  via site-specific logic (API calls, catalogue parsing, etc.).
"""

from __future__ import annotations

import abc
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import requests

__all__ = ["BaseSiteModule"]

log = logging.getLogger(__name__)


class BaseSiteModule(abc.ABC):
    """Base class for all site-specific download modules.

    Parameters
    ----------
    session:
        An optional :class:`requests.Session` for making HTTP requests.
        If ``None``, the module should create its own session when needed.
    """

    #: Human-readable name shown in log messages.
    name: str = "BaseSiteModule"

    #: Host patterns that this module handles (informational).
    hosts: list[str] = []

    def __init__(self, session: "requests.Session | None" = None) -> None:
        self.session = session

    @abc.abstractmethod
    def matches(self, url: str) -> bool:
        """Return ``True`` if this module should be applied for *url*.

        Implementations typically check the URL's hostname or path pattern.
        """

    @abc.abstractmethod
    def extra_urls(self, url: str) -> set[str]:
        """Return additional download URLs for the given start *url*.

        This method is called **once** when the crawl begins.  It may make
        HTTP requests (using ``self.session``) to discover download links
        that are not present in the static HTML (e.g. AJAX API responses,
        catalogue files, hidden CDN links).

        Returns
        -------
        set[str]
            Absolute URLs to download.
        """
