"""
huawei_crawler.config
=====================
Shared configuration constants used throughout the package.
"""

import os

# ---------------------------------------------------------------------------
# Router defaults
# ---------------------------------------------------------------------------
DEFAULT_HOST     = "192.168.100.1"
DEFAULT_USER     = os.environ.get("ROUTER_USER", "Mega_gpon")
DEFAULT_PASSWORD = os.environ.get("ROUTER_PASSWORD", "")
DEFAULT_OUTPUT   = "downloaded_site"

# ---------------------------------------------------------------------------
# Router URL paths
# ---------------------------------------------------------------------------
LOGIN_PAGE     = "/index.asp"
LOGIN_CGI      = "/login.cgi"
RAND_COUNT_URL = "/asp/GetRandCount.asp"
RAND_INFO_URL  = "/asp/GetRandInfo.asp"       # DVODACOM2WIFI (PBKDF2 path)
TOKEN_URL      = "/html/ssmp/common/GetRandToken.asp"  # authenticated token heartbeat

# ---------------------------------------------------------------------------
# Timing / retry settings
# ---------------------------------------------------------------------------
REQUEST_TIMEOUT         = 15    # seconds per HTTP request
DELAY_BETWEEN_REQUESTS  = 0.15  # polite crawl delay (seconds)
MAX_RELOGIN_ATTEMPTS    = 3     # re-login retries per session expiry event
SESSION_HEARTBEAT_EVERY = 20    # heartbeat every N successful fetches
MAX_403_TOKEN_RETRY     = 1     # how many times to retry a 403 with a fresh token

# ---------------------------------------------------------------------------
# Content types that are parsed for further links
# ---------------------------------------------------------------------------
CRAWLABLE_TYPES = frozenset({
    "text/html",
    "application/xhtml+xml",
    "application/javascript",
    "text/javascript",
    "text/css",
    "text/plain",
    "application/json",
    "application/xml",
    "text/xml",
})

# ---------------------------------------------------------------------------
# Session / security
# ---------------------------------------------------------------------------

# All three markers must appear together for a genuine login-form response.
LOGIN_MARKERS = ("txt_Username", "txt_Password", "loginbutton")

# Maximum length for a valid X_HW_Token string.
# Real tokens from GetRandCount.asp / GetRandToken.asp are short numeric or
# hex strings (typically 10-20 chars).  Anything longer almost certainly means
# the endpoint returned an HTML error page (which must NOT be stored as a token).
MAX_TOKEN_LENGTH = 64

# URL path patterns for write-action endpoints that must NEVER be crawled.
import re
BLOCKED_PATH_RE = re.compile(
    r"/(logout|reboot|factory|restore|reset|upgrade\.cgi|getajax\.cgi)\b",
    re.IGNORECASE,
)

# Login-interface pages that always return the login form after authentication.
# Fetching them post-auth would trigger false session-expiry detection.
AUTH_PAGE_PATHS: frozenset = frozenset(["/login.asp", "/index.asp"])
