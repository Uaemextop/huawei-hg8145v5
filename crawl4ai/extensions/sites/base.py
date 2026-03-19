"""
crawl4ai.extensions.sites.base – Abstract base class for site modules.

Every site-specific module must subclass :class:`BaseSiteModule` and
implement:

* :meth:`matches` – Return ``True`` if this module applies to the given URL.
* :meth:`generate_index` – Dynamically discover files via site APIs and
  return a list of :class:`FileEntry` dicts with metadata + download URL.

The downloader writes the returned entries to a ``file_index.md`` Markdown
table instead of downloading the actual files.
"""

from __future__ import annotations

import abc
import logging
from typing import TYPE_CHECKING, TypedDict

if TYPE_CHECKING:
    import requests

__all__ = ["BaseSiteModule", "FileEntry"]

log = logging.getLogger(__name__)


class FileEntry(TypedDict, total=False):
    """Metadata for a single discoverable file.

    Only ``name`` and ``url`` are required; the rest are optional.
    """
    name: str
    url: str
    size: str
    version: str
    release_date: str
    category: str
    os: str
    description: str
    source: str       # Which API/endpoint discovered this file
    product: str      # Which product this file belongs to


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
    def generate_index(self, url: str) -> list[FileEntry]:
        """Dynamically discover files and return their metadata.

        This method is called **once** when the crawl begins.  It should
        make HTTP requests (using ``self.session``) to site-specific APIs
        and return a list of :class:`FileEntry` dicts containing file
        metadata (name, size, version, release date, category, OS,
        description) and the download URL.

        The downloader will write these entries to a ``file_index.md``
        Markdown file instead of downloading the actual files.

        Returns
        -------
        list[FileEntry]
            One entry per discoverable file.
        """

    def page_urls(self, url: str) -> list[str]:
        """Return extra page URLs for the crawler to visit.

        Site modules can override this to dynamically discover additional
        pages (product pages, category pages, etc.) that the regular HTML
        link extraction might miss — for example, pages rendered by a SPA
        framework where links are in JavaScript, not in ``<a href>`` tags.

        The returned URLs are added to the crawler queue at depth 0.

        Returns
        -------
        list[str]
            Additional page URLs to crawl.  Default is an empty list.
        """
        return []
