"""
Master link-extraction dispatcher.

Delegates to the appropriate sub-extractor based on Content-Type and
file extension.
"""

import urllib.parse

from web_crawler.extraction.css import extract_css_urls
from web_crawler.extraction.html_parser import extract_html_attrs
from web_crawler.extraction.javascript import extract_js_paths
from web_crawler.extraction.json_extract import extract_json_paths


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

    elif ct in ("text/plain", "text/xml", "application/xml",
                "application/rss+xml", "application/atom+xml"):
        found |= extract_js_paths(content, url, base)

    return found
