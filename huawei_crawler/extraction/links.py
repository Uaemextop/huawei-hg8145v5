"""Master link-extraction dispatcher."""

import urllib.parse

from .css import _extract_css_urls
from .html_parser import _extract_html_attrs
from .javascript import _extract_js_paths
from .json_extract import _extract_json_paths


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
