"""
huawei_crawler.extract.core
============================
Master link-extraction dispatcher.

Imports the individual extractor modules (css, js, html) and wires them
together with the URL normalisation utility so each sub-extractor receives
the correct ``normalise`` / ``extract_*`` callables.

Public function
---------------
    extract_links(content, content_type, url, base) -> set[str]
"""

from __future__ import annotations

import json
import urllib.parse

from .css  import extract_css_urls  as _raw_extract_css
from .js   import extract_js_paths  as _raw_extract_js
from .html import extract_html_attrs as _raw_extract_html
from ..utils import normalise_url


# ---------------------------------------------------------------------------
# Bound helpers – inject normalise + cross-references
# ---------------------------------------------------------------------------

def _extract_css(css: str, page_url: str, base: str) -> set:
    return _raw_extract_css(css, page_url, base, normalise_url)


def _extract_html(html: str, page_url: str, base: str) -> set:
    return _raw_extract_html(html, page_url, base, normalise_url, _extract_css, _extract_js)


def _extract_js(js: str, page_url: str, base: str) -> set:
    return _raw_extract_js(js, page_url, base, normalise_url, _extract_html)


# ---------------------------------------------------------------------------
# JSON helper
# ---------------------------------------------------------------------------

def _extract_json(text: str, page_url: str, base: str) -> set:
    """
    Parse JSON responses and extract any string values that look like URL paths.
    Handles both proper JSON and JS-style objects returned by Huawei's getajax.cgi.
    """
    found: set = set()
    try:
        obj = json.loads(text)
        queue = [obj]
        while queue:
            item = queue.pop()
            if isinstance(item, dict):
                queue.extend(item.values())
            elif isinstance(item, list):
                queue.extend(item)
            elif isinstance(item, str) and item.startswith("/"):
                n = normalise_url(item, page_url, base)
                if n:
                    found.add(n)
    except (json.JSONDecodeError, ValueError):
        pass
    return found


# ---------------------------------------------------------------------------
# Public dispatcher
# ---------------------------------------------------------------------------

def extract_links(
    content: "bytes | str",
    content_type: str,
    url: str,
    base: str,
) -> set:
    """
    Master link-extraction dispatcher.  Returns a set of absolute URLs found
    in *content*, parsed according to *content_type*.

    * ASP files are always treated as HTML regardless of the Content-Type header.
    * JSON responses are scanned for string values that look like URL paths.
    * All text responses also run through the JS extractor as a fallback so
      path literals embedded in any text format are never missed.
    """
    found: set = set()
    ct = content_type.split(";")[0].strip().lower()

    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")

    parsed_url = urllib.parse.urlparse(url)
    is_asp = parsed_url.path.lower().endswith(".asp")

    if ct in ("text/html", "application/xhtml+xml") or is_asp:
        found |= _extract_html(content, url, base)
        found |= _extract_js(content, url, base)

    elif ct in ("application/javascript", "text/javascript"):
        found |= _extract_js(content, url, base)

    elif ct == "text/css":
        found |= _extract_css(content, url, base)

    elif ct in ("application/json", "text/json"):
        found |= _extract_json(content, url, base)
        found |= _extract_js(content, url, base)

    elif ct in ("text/plain", "text/xml", "application/xml"):
        found |= _extract_js(content, url, base)

    return found
