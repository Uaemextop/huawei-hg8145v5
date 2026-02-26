"""HTML attribute extraction using BeautifulSoup."""

import re

from bs4 import BeautifulSoup

from ..session import _BS4_PARSER
from ..utils.url import normalise_url
from .css import _extract_css_urls
from .javascript import _extract_js_paths


def _extract_html_attrs(html: str, page_url: str, base: str) -> set[str]:
    """
    Use BeautifulSoup (with lxml when available) to extract every resource
    URL from HTML/ASP content.  Also parses inline <style> and <script>.
    """
    found: set[str] = set()

    def _add(raw: str) -> None:
        n = normalise_url(raw.strip(), page_url, base)
        if n:
            found.add(n)

    try:
        soup = BeautifulSoup(html, _BS4_PARSER)
    except Exception:
        return found

    # --- Standard tag attributes ---
    attr_map = {
        "a":       ["href"],
        "link":    ["href"],
        "script":  ["src"],
        "img":     ["src", "data-src"],
        "source":  ["src", "srcset"],
        "iframe":  ["src"],
        "frame":   ["src"],
        "form":    ["action"],
        "input":   ["src"],
        "body":    ["background"],
        "meta":    [],         # handled below for http-equiv=refresh
        "object":  ["data"],
        "embed":   ["src"],
        "audio":   ["src"],
        "video":   ["src", "poster"],
        "track":   ["src"],
    }
    for tag, attrs in attr_map.items():
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

    # --- Inline <style> blocks ---
    for style_el in soup.find_all("style"):
        found |= _extract_css_urls(style_el.get_text(), page_url, base)

    # --- Inline <script> blocks ---
    for script_el in soup.find_all("script"):
        if not script_el.get("src"):
            found |= _extract_js_paths(script_el.get_text(), page_url, base)

    return found
