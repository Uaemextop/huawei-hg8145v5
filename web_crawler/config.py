"""
Configuration constants for the generic web crawler.
"""

import re

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_OUTPUT = "downloaded_site"
DEFAULT_MAX_DEPTH = 0          # 0 = unlimited
DEFAULT_DELAY = 0.25           # seconds between requests
DEFAULT_MAX_PAGES = 0          # 0 = unlimited

# ---------------------------------------------------------------------------
# Crawler tuning
# ---------------------------------------------------------------------------
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3

# ---------------------------------------------------------------------------
# Content types parsed for further links
# ---------------------------------------------------------------------------
CRAWLABLE_TYPES = {
    "text/html",
    "application/xhtml+xml",
    "application/javascript",
    "text/javascript",
    "text/css",
    "text/plain",
    "application/json",
    "application/xml",
    "text/xml",
}

# ---------------------------------------------------------------------------
# Blocked URL patterns (dangerous / non-crawlable endpoints)
# ---------------------------------------------------------------------------
BLOCKED_PATH_RE = re.compile(
    r"(logout|signout|delete|remove|unsubscribe)\b",
    re.IGNORECASE,
)
