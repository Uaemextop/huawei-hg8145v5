"""Configuration constants for the Huawei HG8145V5 crawler."""

import os
import re

DEFAULT_HOST = "192.168.100.1"
# Credentials can also be supplied via ROUTER_USER / ROUTER_PASSWORD env vars
DEFAULT_USER = os.environ.get("ROUTER_USER", "Mega_gpon")
DEFAULT_PASSWORD = os.environ.get("ROUTER_PASSWORD", "")
DEFAULT_OUTPUT = "downloaded_site"

LOGIN_PAGE     = "/index.asp"
LOGIN_CGI      = "/login.cgi"
RAND_COUNT_URL = "/asp/GetRandCount.asp"
RAND_INFO_URL  = "/asp/GetRandInfo.asp"    # used by DVODACOM2WIFI (PBKDF2 path)
TOKEN_URL      = "/html/ssmp/common/GetRandToken.asp"   # authenticated token heartbeat

REQUEST_TIMEOUT            = 15    # seconds per HTTP request
DELAY_BETWEEN_REQUESTS     = 0.15  # polite crawl delay (seconds)
MAX_RELOGIN_ATTEMPTS       = 3     # re-login retries per session expiry event
SESSION_HEARTBEAT_EVERY    = 20    # POST to TOKEN_URL every N successful fetches
MAX_403_TOKEN_RETRY        = 1     # how many times to retry a 403 with a fresh token

# Content types whose response body is parsed for further links
CRAWLABLE_TYPES = {
    "text/html",
    "application/xhtml+xml",
    "application/javascript",
    "text/javascript",
    "text/css",
    "text/plain",
    "application/json",        # router data APIs may return JSON with path refs
    "application/xml",
    "text/xml",
}

# Signals that the session has expired – checked only against HTML responses
_LOGIN_MARKERS = ("txt_Username", "txt_Password", "loginbutton")

# URL path patterns for write-action endpoints that must NEVER be crawled.
# • logout – terminates the session
# • reboot / factory / restore / reset – make irreversible hardware changes
# • upgrade.cgi – firmware upgrade (potentially bricking)
# • getajax.cgi without a meaningful ObjPath – the data API returns
#   hex-encoded TR-069 objects, not HTML; specific ObjPath URLs discovered
#   from JS can still be fetched (they are allowed through).
_BLOCKED_PATH_RE = re.compile(
    r"/(logout|reboot|factory|restore|reset|upgrade\.cgi|getajax\.cgi)\b",
    re.IGNORECASE,
)

# Login-interface pages that ALWAYS return the login form after authentication.
# Crawling them via a GET causes is_session_expired() to fire a false positive,
# which triggers an infinite re-login loop.  We save them pre-auth instead and
# skip HTTP fetches for them during BFS.
_AUTH_PAGE_PATHS: frozenset[str] = frozenset(["/login.asp", "/index.asp", "/"])
