"""HTML/ASP attribute extraction via BeautifulSoup.

Delegates to :mod:`crawl4ai.extensions.extraction`.
"""

from crawl4ai.extensions.extraction import extract_html_attrs  # noqa: F401

__all__ = ["extract_html_attrs"]
