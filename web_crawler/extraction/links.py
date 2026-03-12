"""
Master link-extraction dispatcher.

Delegates to the appropriate sub-extractor based on Content-Type and
file extension.
"""

import html as html_mod
import re
import urllib.parse

from web_crawler.extraction.css import extract_css_urls
from web_crawler.extraction.html_parser import extract_html_attrs
from web_crawler.extraction.javascript import extract_js_paths
from web_crawler.extraction.json_extract import extract_json_paths
from web_crawler.utils.url import normalise_url


# Tags in XML feeds that commonly contain URLs.
_XML_URL_TAG_RE = re.compile(
    r"<(?:link|url|loc|folder_url|image:loc|video:content_loc"
    r"|video:player_loc|xhtml:link|enclosure|guid)"
    r"[^>]*>([^<]+)</",
    re.I,
)

# Attribute URLs in XML tags (e.g. <source url="...">, <enclosure url="...">)
_XML_ATTR_URL_RE = re.compile(
    r"""(?:url|href)\s*=\s*["']([^"']+)["']""",
    re.I,
)


def _extract_xml_urls(xml: str, page_url: str, base: str) -> set[str]:
    """Extract URLs from RSS, Atom and sitemap XML feeds.

    Handles ``&amp;`` entity-encoded URLs commonly found in XML content.
    Extracts URLs from both tag text content (``<link>URL</link>``) and
    tag attributes (``<source url="URL">``).
    """
    found: set[str] = set()

    for m in _XML_URL_TAG_RE.finditer(xml):
        raw = m.group(1).strip()
        if raw:
            # XML content has &amp; entity encoding
            raw = html_mod.unescape(raw)
            n = normalise_url(raw, page_url, base)
            if n:
                found.add(n)

    for m in _XML_ATTR_URL_RE.finditer(xml):
        raw = m.group(1).strip()
        if raw:
            raw = html_mod.unescape(raw)
            n = normalise_url(raw, page_url, base)
            if n:
                found.add(n)

    return found


def extract_links(
    content: bytes | str,
    content_type: str,
    url: str,
    base: str,
) -> set[str]:
    """
    Return a set of absolute URLs found in *content*, parsed according to
    *content_type*.

    PHP and ASP files are always treated as HTML regardless of Content-Type.
    """
    found: set[str] = set()
    ct = content_type.split(";")[0].strip().lower()

    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")

    parsed_url = urllib.parse.urlparse(url)
    path_lower = parsed_url.path.lower()
    is_html_ext = path_lower.endswith((".asp", ".php", ".html", ".htm"))

    if ct in ("text/html", "application/xhtml+xml",
              "application/x-httpd-php", "text/x-php",
              "application/php") or is_html_ext:
        found |= extract_html_attrs(content, url, base)
        found |= extract_js_paths(content, url, base)

    elif ct in ("application/javascript", "text/javascript"):
        found |= extract_js_paths(content, url, base)

    elif ct in ("text/css",):
        found |= extract_css_urls(content, url, base)

    elif ct in ("application/json", "text/json"):
        found |= extract_json_paths(content, url, base)
        found |= extract_js_paths(content, url, base)

    elif ct in ("text/xml", "application/xml",
                "application/rss+xml", "application/atom+xml"):
        found |= _extract_xml_urls(content, url, base)
        found |= extract_js_paths(content, url, base)

    elif ct == "text/plain":
        found |= extract_js_paths(content, url, base)

    return found
