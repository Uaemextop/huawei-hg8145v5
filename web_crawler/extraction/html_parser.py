"""
HTML/ASP attribute extraction via BeautifulSoup.
"""

import re

from web_crawler.utils.url import normalise_url
from web_crawler.extraction.css import extract_css_urls
from web_crawler.extraction.javascript import extract_js_paths

try:
    import lxml  # noqa: F401
    _BS4_PARSER = "lxml"
except ImportError:
    _BS4_PARSER = "html.parser"

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None  # type: ignore[misc,assignment]


def extract_html_attrs(html: str, page_url: str, base: str) -> set[str]:
    """
    Extract every resource URL from HTML/ASP content using BeautifulSoup.
    Also parses inline ``<style>`` and ``<script>`` blocks.
    """
    found: set[str] = set()

    if BeautifulSoup is None:
        return found

    def _add(raw: str, *, allow_external: bool = False) -> None:
        n = normalise_url(raw.strip(), page_url, base,
                          allow_external=allow_external)
        if n:
            found.add(n)

    try:
        soup = BeautifulSoup(html, _BS4_PARSER)
    except Exception:
        return found

    # Tags whose media attributes may reference external CDNs
    _MEDIA_TAGS = {"video", "source", "audio", "track"}

    attr_map = {
        "a":       ["href"],
        "link":    ["href"],
        "script":  ["src"],
        "img":     ["src", "data-src", "data-lazy-src"],
        "source":  ["src", "srcset", "data-src"],
        "iframe":  ["src"],
        "frame":   ["src"],
        "form":    ["action"],
        "input":   ["src"],
        "body":    ["background"],
        "meta":    [],
        "object":  ["data"],
        "embed":   ["src"],
        "audio":   ["src", "data-src"],
        "video":   ["src", "poster", "data-src", "data-lazy-src"],
        "track":   ["src"],
    }
    for tag, attrs in attr_map.items():
        is_media = tag in _MEDIA_TAGS
        for el in soup.find_all(tag):
            for attr in attrs:
                val = el.get(attr)
                if val:
                    _add(val, allow_external=is_media)
            if tag == "meta":
                content = el.get("content", "")
                m = re.search(r"url=([^\s;\"']+)", content, re.I)
                if m:
                    _add(m.group(1))
                # Schema.org itemprop with URL values (contentURL,
                # embedURL, thumbnailUrl, url, image, etc.)
                itemprop = (el.get("itemprop") or "").lower()
                if itemprop and content:
                    _url_props = {
                        "contenturl", "embedurl", "thumbnailurl",
                        "url", "image",
                    }
                    if itemprop in _url_props and content.startswith(
                        ("http://", "https://", "/")
                    ):
                        _add(content, allow_external=True)

    for style_el in soup.find_all("style"):
        found |= extract_css_urls(style_el.get_text(), page_url, base)

    for script_el in soup.find_all("script"):
        if not script_el.get("src"):
            found |= extract_js_paths(script_el.get_text(), page_url, base)

    return found
