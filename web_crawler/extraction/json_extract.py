"""
JSON path extraction.
"""

import json
import re

from web_crawler.utils.url import normalise_url

# WP REST API "self-referential" URL patterns that create queue loops.
# These are embedded in every REST response under ``_links`` / ``href``
# and generate exponential queue growth when crawled recursively.
# NOTE: some patterns overlap with BLOCKED_PATH_RE in config.py; that is
# intentional – filtering here prevents URL *generation*, while
# BLOCKED_PATH_RE prevents URL *enqueue*.  Defence in depth.
_WP_REST_LOOP_RE = re.compile(
    r"/wp-json/wp/v2/[^/]+/\d+/revisions"           # post revisions (401)
    r"|/wp-json/wp/v2/[^/]+\?[^\"]*\bparent=\d+"     # parent filter
    r"|/wp-json/wc/store/v1/cart/"                     # cart actions (404)
    r"|/wp-json/wc/store/v1/batch\b"                   # batch endpoint (404)
    r"|/wp-json/wc/store/v1/checkout\b"                # checkout (404)
    r"|/wp-json/wc-telemetry/"                         # telemetry (404)
    r"|/wp-json/wccom-site/"                           # wccom-site (404)
    r"|/wp-json/wp/v2/(?:posts|pages|categories|tags"
    r"|users|media|comments)\?",                       # paginated collection queries
    re.IGNORECASE,
)


def extract_json_paths(text: str, page_url: str, base: str) -> set[str]:
    """
    Parse JSON responses and extract string values that look like URL paths
    or absolute URLs on the same host (e.g. WordPress REST API responses).

    Filters out self-referential WP REST API links (revisions, pagination,
    cart actions) that would cause unbounded queue growth.
    """
    found: set[str] = set()
    try:
        obj = json.loads(text)
        queue = [obj]
        while queue:
            item = queue.pop()
            if isinstance(item, dict):
                queue.extend(item.values())
            elif isinstance(item, list):
                queue.extend(item)
            elif isinstance(item, str):
                if item.startswith("/") or item.startswith(("http://", "https://")):
                    # Skip WP REST API self-referential links that cause loops
                    if _WP_REST_LOOP_RE.search(item):
                        continue
                    n = normalise_url(item, page_url, base)
                    if n:
                        found.add(n)
    except (json.JSONDecodeError, ValueError):
        pass
    return found
