"""Link extraction registry — dispatches to specialized extractors.

Delegates to :mod:`crawl4ai.extensions.extraction`, which provides a
unified extraction pipeline (HTML, CSS, JS, JSON, cloud storage).
"""

from crawl4ai.extensions.extraction import (  # noqa: F401
    extract_all,
    extract_links,
    extract_cloud_links,
    extract_html_attrs,
    extract_css_urls,
    extract_js_paths,
    extract_json_paths,
)

__all__ = [
    "extract_all",
    "extract_links",
    "extract_cloud_links",
    "extract_html_attrs",
    "extract_css_urls",
    "extract_js_paths",
    "extract_json_paths",
]
