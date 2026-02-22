"""
Configuration constants for the Huawei HG8145V5 crawler.
"""

import os
import re

# ---------------------------------------------------------------------------
# Network / host defaults
# ---------------------------------------------------------------------------
DEFAULT_HOST = "192.168.100.1"
DEFAULT_USER = os.environ.get("ROUTER_USER", "Mega_gpon")
DEFAULT_PASSWORD = os.environ.get("ROUTER_PASSWORD", "")
DEFAULT_OUTPUT = "downloaded_site"

# ---------------------------------------------------------------------------
# Router endpoint paths
# ---------------------------------------------------------------------------
LOGIN_PAGE = "/index.asp"
LOGIN_CGI = "/login.cgi"
RAND_COUNT_URL = "/asp/GetRandCount.asp"
RAND_INFO_URL = "/asp/GetRandInfo.asp"
TOKEN_URL = "/html/ssmp/common/GetRandToken.asp"

# ---------------------------------------------------------------------------
# Crawler tuning
# ---------------------------------------------------------------------------
REQUEST_TIMEOUT = 15
DELAY_BETWEEN_REQUESTS = 0.15
MAX_RELOGIN_ATTEMPTS = 3
SESSION_HEARTBEAT_EVERY = 20
MAX_403_TOKEN_RETRY = 1

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
# Session-expiry detection markers (HTML body)
# ---------------------------------------------------------------------------
LOGIN_MARKERS = ("txt_Username", "txt_Password", "loginbutton")

# ---------------------------------------------------------------------------
# Blocked URL patterns (write-action endpoints)
# ---------------------------------------------------------------------------
BLOCKED_PATH_RE = re.compile(
    r"/(logout|reboot|factory|restore|reset|upgrade\.cgi|getajax\.cgi)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Login-interface pages that always return the login form post-auth.
# Fetching them triggers false session-expiry detection; they are saved
# pre-auth instead and skipped during the BFS crawl.
# ---------------------------------------------------------------------------
AUTH_PAGE_PATHS: frozenset[str] = frozenset(["/login.asp", "/index.asp"])
