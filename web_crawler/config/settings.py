"""Configuration constants for the generic web crawler.

Delegates to :mod:`crawl4ai.extensions.settings` — the canonical
configuration module shared by both ``web_crawler`` and ``crawl4ai``.

HP-specific constants (``HP_DOWNLOAD_HOSTS``, ``HP_CATALOG_URLS``) that
were previously defined here are now in the HP site module
(:mod:`crawl4ai.extensions.sites.hp_support`).
"""

# Re-export everything from crawl4ai.extensions.settings so that
# ``from web_crawler.config.settings import X`` keeps working.
from crawl4ai.extensions.settings import *  # noqa: F401,F403
from crawl4ai.extensions.settings import __all__  # noqa: F401
from crawl4ai.extensions.settings import auto_concurrency  # noqa: F401
