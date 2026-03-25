"""CSS URL extraction helpers.

Delegates to :mod:`crawl4ai.extensions.extraction`.
"""

from crawl4ai.extensions.extraction import extract_css_urls  # noqa: F401

__all__ = ["extract_css_urls"]
