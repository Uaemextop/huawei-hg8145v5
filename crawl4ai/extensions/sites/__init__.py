"""
crawl4ai.extensions.sites – Site-specific download modules.

Each module in this package defines rules and logic for a particular
website.  When the :class:`~crawl4ai.extensions.downloader.SiteDownloader`
starts a crawl, it iterates over the **registry** and checks each module's
:pymethod:`matches` method against the target URL.  If a module matches,
its :pymethod:`generate_index` method is called to dynamically discover
files via site-specific APIs and return a list of
:class:`FileEntry` dicts with metadata (name, size, version, release
date, category, OS, description) and a download URL.

The downloader writes these entries to a ``file_index.md`` Markdown table
instead of downloading the actual files.

Creating a new site module
--------------------------

1. Create ``crawl4ai/extensions/sites/my_site.py``.
2. Subclass :class:`BaseSiteModule` and implement ``matches()`` and
   ``generate_index()``.
3. Add the class to the ``_REGISTRY`` list in this ``__init__.py``.

The downloader will automatically pick up the module.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .base import BaseSiteModule, FileEntry
from .ami_bios import AMIBiosModule
from .hp_support import HPSupportModule

if TYPE_CHECKING:
    import requests

__all__ = [
    "AMIBiosModule",
    "BaseSiteModule",
    "FileEntry",
    "HPSupportModule",
    "get_matching_modules",
]

log = logging.getLogger(__name__)

# ── Module registry ──────────────────────────────────────────────────────
# Add new site modules here.  Order does not matter – all matching modules
# are applied, not just the first one.
_REGISTRY: list[type[BaseSiteModule]] = [
    AMIBiosModule,
    HPSupportModule,
]


def get_matching_modules(
    url: str,
    session: "requests.Session | None" = None,
) -> list[BaseSiteModule]:
    """Return instantiated site modules whose ``matches()`` returns *True*
    for *url*.

    Parameters
    ----------
    url:
        The crawl start URL.
    session:
        An optional :class:`requests.Session` that modules may use for
        API calls.  If ``None``, modules should create their own.

    Returns
    -------
    list[BaseSiteModule]
        Zero or more module instances.
    """
    matched: list[BaseSiteModule] = []
    for cls in _REGISTRY:
        try:
            inst = cls(session=session)
            if inst.matches(url):
                log.debug("Site module %s matched URL %s", cls.__name__, url)
                matched.append(inst)
        except (TypeError, AttributeError, ValueError, ImportError) as exc:
            log.debug("Error checking site module %s: %s", cls.__name__, exc)
    return matched
