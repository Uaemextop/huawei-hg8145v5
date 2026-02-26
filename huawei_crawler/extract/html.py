"""
huawei_crawler.extract.html
============================
Extracts resource URLs from HTML / ASP content using BeautifulSoup.

Handles:
* Standard tag attributes (href, src, action, data-src, …)
* ``<meta http-equiv="refresh" content="0;url=…">``
* Inline ``<style>`` blocks (delegated to css module)
* Inline ``<script>`` blocks (delegated to js module)
"""

import re
import logging

log = logging.getLogger("hg8145v5-crawler")

try:
    import lxml  # noqa: F401 – used as BeautifulSoup parser backend
    _BS4_PARSER = "lxml"
except ImportError:
    _BS4_PARSER = "html.parser"

try:
    from bs4 import BeautifulSoup
    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False


# HTML tag → list of URL-bearing attributes
_ATTR_MAP = {
    "a":      ["href"],
    "link":   ["href"],
    "script": ["src"],
    "img":    ["src", "data-src"],
    "source": ["src", "srcset"],
    "iframe": ["src"],
    "frame":  ["src"],
    "form":   ["action"],
    "input":  ["src"],
    "body":   ["background"],
    "meta":   [],          # handled separately for http-equiv=refresh
    "object": ["data"],
    "embed":  ["src"],
    "audio":  ["src"],
    "video":  ["src", "poster"],
    "track":  ["src"],
}


def extract_html_attrs(
    html: str, page_url: str, base: str, normalise, extract_css_urls, extract_js_paths
) -> set:
    """
    Use BeautifulSoup to extract every resource URL from HTML/ASP content.
    Also parses inline ``<style>`` and ``<script>`` blocks.

    Parameters
    ----------
    html             : Raw HTML/ASP text.
    page_url         : Absolute URL of the page (for relative resolution).
    base             : Router base URL.
    normalise        : URL normalisation callable.
    extract_css_urls : CSS extraction callable.
    extract_js_paths : JS extraction callable (receives this function back for
                       recursive ``document.write()`` handling).
    """
    found: set = set()

    if not _BS4_AVAILABLE:
        return found

    def _add(raw: str) -> None:
        n = normalise(raw.strip(), page_url, base)
        if n:
            found.add(n)

    try:
        soup = BeautifulSoup(html, _BS4_PARSER)
    except Exception:
        return found

    # Standard tag attributes
    for tag, attrs in _ATTR_MAP.items():
        for el in soup.find_all(tag):
            for attr in attrs:
                val = el.get(attr)
                if val:
                    _add(val)
            # meta http-equiv="refresh" content="0;url=/page.asp"
            if tag == "meta":
                content = el.get("content", "")
                m = re.search(r"url=([^\s;\"']+)", content, re.I)
                if m:
                    _add(m.group(1))

    # Inline <style> blocks
    for style_el in soup.find_all("style"):
        found |= extract_css_urls(style_el.get_text(), page_url, base)

    # Inline <script> blocks
    for script_el in soup.find_all("script"):
        if not script_el.get("src"):
            found |= extract_js_paths(script_el.get_text(), page_url, base)

    return found
