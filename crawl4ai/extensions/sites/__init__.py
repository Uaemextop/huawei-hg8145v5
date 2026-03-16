"""
crawl4ai.extensions.sites – Site-specific download modules.

Each module in this package defines rules and logic for a particular
website.  When the :class:`~crawl4ai.extensions.downloader.SiteDownloader`
starts a crawl, it iterates over the **registry** and checks each module's
:pymethod:`matches` method against the target URL.  If a module matches,
its :pymethod:`extra_urls` method is called to inject additional download
URLs that cannot be discovered by simple HTML link scanning (e.g. AJAX
API endpoints, catalogue files, hidden download links).

Creating a new site module
--------------------------

1. Create ``crawl4ai/extensions/sites/my_site.py``.
2. Subclass :class:`BaseSiteModule` and implement ``matches()`` and
   ``extra_urls()``.
3. Add the class to the ``_REGISTRY`` list in this ``__init__.py``.

The downloader will automatically pick up the module.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .base import BaseSiteModule
from .hp_support import HPSupportModule

if TYPE_CHECKING:
    import requests

__all__ = [
    "BaseSiteModule",
    "HPSupportModule",
    "get_matching_modules",
]

log = logging.getLogger(__name__)

# ── Module registry ──────────────────────────────────────────────────────
# Add new site modules here.  Order does not matter – all matching modules
# are applied, not just the first one.
_REGISTRY: list[type[BaseSiteModule]] = [
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
        except Exception as exc:  # noqa: BLE001
            log.debug("Error checking site module %s: %s", cls.__name__, exc)
    return matched
