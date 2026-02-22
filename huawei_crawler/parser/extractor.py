"""
Link extraction from various content types.

This module provides unified extraction of URLs from HTML, JavaScript, CSS, and JSON content.
For implementation details, see crawler.py (lines 545-823).
"""

import json
import re
import sys
import urllib.parse

try:
    from bs4 import BeautifulSoup
except ImportError:
    sys.exit("Missing dependency. Run:  pip install -r requirements.txt")

try:
    import lxml  # noqa: F401 – used as BeautifulSoup parser backend
    _BS4_PARSER = "lxml"
except ImportError:
    _BS4_PARSER = "html.parser"


# Import core extraction patterns and functions from the main crawler
# This provides a transitional architecture while we complete the modularization
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from crawler import (
    _extract_html_attrs,
    _extract_js_paths,
    _extract_css_urls,
    _extract_json_paths,
)


def extract_links(
    content: bytes | str,
    content_type: str,
    url: str,
    base: str,
) -> set[str]:
    """
    Master link-extraction dispatcher.  Returns a set of absolute URLs found
    in *content*, parsed according to *content_type*.

    • ASP files are always treated as HTML regardless of the Content-Type header.
    • JSON responses are scanned for string values that look like URL paths.
    • All text responses also run through the JS extractor as a fallback so
      path literals embedded in any text format are never missed.

    Args:
        content: Response content (bytes or string)
        content_type: Content-Type header value
        url: URL of the page being parsed
        base: Base URL of the router

    Returns:
        Set of absolute URLs extracted from the content
    """
    found: set[str] = set()
    ct = content_type.split(";")[0].strip().lower()

    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")

    parsed_url = urllib.parse.urlparse(url)
    is_asp = parsed_url.path.lower().endswith(".asp")

    if ct in ("text/html", "application/xhtml+xml") or is_asp:
        found |= _extract_html_attrs(content, url, base)
        found |= _extract_js_paths(content, url, base)

    elif ct in ("application/javascript", "text/javascript"):
        found |= _extract_js_paths(content, url, base)

    elif ct in ("text/css",):
        found |= _extract_css_urls(content, url, base)

    elif ct in ("application/json", "text/json"):
        found |= _extract_json_paths(content, url, base)
        found |= _extract_js_paths(content, url, base)

    elif ct in ("text/plain", "text/xml", "application/xml"):
        found |= _extract_js_paths(content, url, base)

    return found


__all__ = ["extract_links"]
