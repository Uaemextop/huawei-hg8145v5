"""Link extraction registry — dispatches to specialized extractors."""

from web_crawler.extraction.html import extract_html_attrs
from web_crawler.extraction.css import extract_css_urls
from web_crawler.extraction.javascript import extract_js_paths
from web_crawler.extraction.json_extract import extract_json_paths
from web_crawler.extraction.google_drive import extract_cloud_links

import urllib.parse


def extract_all(content, content_type, url, base):
    """Extract all links using all available extractors.
    
    Also extracts cloud storage links (Google Drive, Mega, etc.).
    """
    found = set()
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
        found |= extract_cloud_links(content)
    elif ct in ("application/javascript", "text/javascript"):
        found |= extract_js_paths(content, url, base)
        found |= extract_cloud_links(content)
    elif ct in ("text/css",):
        found |= extract_css_urls(content, url, base)
    elif ct in ("application/json", "text/json"):
        found |= extract_json_paths(content, url, base)
        found |= extract_js_paths(content, url, base)
    elif ct in ("text/plain", "text/xml", "application/xml",
                "application/rss+xml", "application/atom+xml"):
        found |= extract_js_paths(content, url, base)

    return found


def extract_links(content, content_type, url, base):
    """Backward-compatible alias for extract_all."""
    return extract_all(content, content_type, url, base)


__all__ = ["extract_all", "extract_links", "extract_cloud_links"]
