#!/usr/bin/env python3
"""
Huawei HG8145V5 Router Web Crawler
====================================
Logs into the router admin panel at http://192.168.100.1 and exhaustively
downloads every reachable page and static asset (HTML/ASP, JS, CSS, images,
fonts, JSON, XML, …) using a recursive BFS that continues until no new URLs
remain.

Features
--------
* Two-step login (anti-CSRF token + Base64-encoded password via /login.cgi)
* Session keep-alive – explicit Connection: keep-alive header so the router
  reuses the same TCP connection and does not expire auth prematurely
* Auto re-login – when a session expiry is detected (HTTP 401 or login-form
  response), cookies are cleared and login is retried; the counter resets to
  zero after every successful response so each expiry gets fresh attempts
* Resume / skip already-downloaded files – at startup the output directory is
  scanned; existing files are marked as visited and their content is parsed
  for undiscovered links so the crawl can continue from where it left off
  without re-fetching anything already on disk (override with --force)
* Deep link extraction from HTML/ASP/JS/CSS:
    - All standard HTML tag attributes (href, src, action, data-src, …)
    - CSS url() and @import
    - JS: Form.setAction(), $.ajax({url:}), window.location, location.href
    - ALL root-relative quoted strings (e.g. '/html/ssmp/wlan.asp')
    - RequestFile= query-parameter values embedded in CGI URLs
    - document.write() contents treated as nested HTML
* ASP responses are parsed as HTML regardless of Content-Type
* Exhaustive: crawls until the BFS queue is completely empty
* Preserves the original server directory structure on disk

Usage (Windows / Linux / macOS)
---------------------------------
    pip install -r requirements.txt

    # Prompted for password if not supplied via env or flag
    python crawler.py

    # Explicit credentials
    python crawler.py --host 192.168.100.1 --user Mega_gpon \\
        --password YOUR_PASSWORD --output downloaded_site

    # Force re-download even if files already exist
    python crawler.py --force

    # Password from environment variable (recommended)
    set ROUTER_PASSWORD=YOUR_PASSWORD   # Windows
    export ROUTER_PASSWORD=YOUR_PASSWORD  # Linux/macOS
    python crawler.py
"""

import argparse
import base64
import logging
import os
import re
import sys
import time
import urllib.parse
from collections import deque
from pathlib import Path

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    sys.exit("Missing dependency. Run:  pip install -r requirements.txt")

try:
    from bs4 import BeautifulSoup
except ImportError:
    sys.exit("Missing dependency. Run:  pip install -r requirements.txt")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("hg8145v5-crawler")

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------
DEFAULT_HOST = "192.168.100.1"
# Credentials can also be supplied via ROUTER_USER / ROUTER_PASSWORD env vars
DEFAULT_USER = os.environ.get("ROUTER_USER", "Mega_gpon")
DEFAULT_PASSWORD = os.environ.get("ROUTER_PASSWORD", "")
DEFAULT_OUTPUT = "downloaded_site"

LOGIN_PAGE = "/index.asp"
LOGIN_CGI = "/login.cgi"
RAND_COUNT_URL = "/asp/GetRandCount.asp"

REQUEST_TIMEOUT = 15          # seconds per HTTP request
DELAY_BETWEEN_REQUESTS = 0.2  # polite crawl delay (seconds)
MAX_RELOGIN_ATTEMPTS = 2      # how many times to retry after session expiry

# Content types whose response body is parsed for further links
CRAWLABLE_TYPES = {
    "text/html",
    "application/xhtml+xml",
    "application/javascript",
    "text/javascript",
    "text/css",
    # The router sometimes serves ASP / CGI responses as plain text
    "text/plain",
}

# Signals that the session has expired – checked only against HTML responses
_LOGIN_MARKERS = ("txt_Username", "txt_Password", "loginbutton")

# URL path patterns for write-action endpoints that must NEVER be crawled.
# Fetching these would terminate the session (logout) or make irreversible
# changes to the router (reboot, factory-reset, firmware upgrade).
_BLOCKED_PATH_RE = re.compile(
    r"/(logout|reboot|factory|restore|reset|upgrade\.cgi)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Session bootstrap
# ---------------------------------------------------------------------------

def build_session(verify_ssl: bool = True) -> requests.Session:
    """Return a requests.Session with retry logic and keep-alive pre-configured."""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = verify_ssl
    # Mimic a real browser so the router does not reject requests based on
    # User-Agent.  Also request keep-alive to reuse the TCP connection.
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Connection": "keep-alive",
        "Keep-Alive": "timeout=60, max=1000",
    })
    return session


def base_url(host: str) -> str:
    return f"http://{host}"


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def b64encode_password(password: str) -> str:
    """
    Replicate the router's  base64encode(Password.value)  from util.js.
    Standard RFC 4648 Base64 over the UTF-8 bytes of the password string.
    """
    return base64.b64encode(password.encode("utf-8")).decode("ascii")


def get_rand_token(session: requests.Session, host: str) -> str:
    """
    POST to /asp/GetRandCount.asp to obtain the one-time anti-CSRF token
    used as 'x.X_HW_Token' in the login form.
    """
    url = base_url(host) + RAND_COUNT_URL
    resp = session.post(url, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    token = resp.text.strip()
    log.debug("X_HW_Token: %s", token)
    return token


def login(session: requests.Session, host: str, username: str, password: str) -> str | None:
    """
    Two-step login for the HG8145V5 admin interface:
      1. GET /index.asp  → router sets initial session cookies
      2. POST /asp/GetRandCount.asp  → obtain anti-CSRF token
      3. POST /login.cgi with UserName, Base64(Password), Language, token

    The pre-login cookie  Cookie=body:Language:english:id=-1  (path=/)
    is set to mimic what the login page's JavaScript does before submission.

    Returns the post-login redirect URL (the admin home page) on success,
    or None on failure.  The caller can use this URL as the starting seed
    and as the Referer for subsequent authenticated requests.
    """
    # Step 1 – load login page so the router sets initial session cookies
    try:
        session.get(base_url(host) + LOGIN_PAGE, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        log.warning("Could not load login page: %s", exc)

    log.debug(
        "Cookies after GET /index.asp: %s",
        dict(session.cookies),
    )

    # Step 2 – get anti-CSRF token
    try:
        token = get_rand_token(session, host)
    except requests.RequestException as exc:
        log.error("Failed to get auth token: %s", exc)
        return None

    # Step 3 – submit credentials
    # Replicate:  var cookie2 = "Cookie=body:Language:english:id=-1;path=/";
    #             document.cookie = cookie2;
    # In JavaScript document.cookie syntax, ';path=/' is a cookie ATTRIBUTE,
    # not part of the value.  Pass it as the path= keyword argument here so
    # the server receives the correct value: 'body:Language:english:id=-1'.
    session.cookies.set(
        "Cookie",
        "body:Language:english:id=-1",
        domain=host,
        path="/",
    )

    payload = {
        "UserName": username,
        "PassWord": b64encode_password(password),
        "Language": "english",
        "x.X_HW_Token": token,
    }

    try:
        resp = session.post(
            base_url(host) + LOGIN_CGI,
            data=payload,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        log.error("Login POST failed: %s", exc)
        return None

    # A successful login redirects away from the login form.
    # If the response still contains the login form, credentials were wrong.
    if any(marker in resp.text for marker in _LOGIN_MARKERS):
        log.error(
            "Login failed – router returned the login form. "
            "Check your credentials."
        )
        return None

    post_login_url = resp.url
    log.info("Login successful (HTTP %s). Post-login URL: %s. Active cookies: %s",
             resp.status_code, post_login_url, list(session.cookies.keys()))
    return post_login_url


def is_session_expired(resp: requests.Response) -> bool:
    """
    Return True only when the router has genuinely redirected to the login form.

    Avoids two classes of false positives that caused session-expiry loops:
      * URL-based FP: 'login' in url matches /Cuscss/login.css, safelogin.js, etc.
        → now checks only the specific login-page paths /index.asp and /login.asp.
      * Body-based FP: JS files contain login marker strings as DOM element IDs
        (e.g. document.getElementById('txt_Password')), CSS contains .loginbutton.
        → now ignores non-HTML content types and requires ALL markers together.
    """
    # A redirect to the specific login-page paths is the most reliable signal.
    # We only match the path (not substrings of other paths).
    final_path = urllib.parse.urlparse(resp.url).path.lower()
    if final_path in ("/index.asp", "/login.asp"):
        return True

    # Non-HTML responses (JS, CSS, images) can legitimately contain login-related
    # identifier strings – skip the body check for them entirely.
    ct = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
    if ct and ct not in ("text/html", "application/xhtml+xml"):
        return False

    # A genuine login form has ALL three markers present at the same time.
    # Using all() prevents a single marker in an HTML snippet from firing.
    return all(marker in resp.text for marker in _LOGIN_MARKERS)


# ---------------------------------------------------------------------------
# URL normalisation
# ---------------------------------------------------------------------------

def normalise_url(raw: str, page_url: str, base: str) -> str | None:
    """
    Convert *raw* to an absolute URL on the same router host.
    Strips cache-buster query strings (pure numeric / hex tokens like
    '?202406291158020553184798') but keeps meaningful query strings so that
    CGI endpoints that require parameters are not broken.

    Returns None for external, data:, javascript:, mailto: URLs.
    """
    raw = raw.strip()
    if not raw or raw.startswith(("data:", "javascript:", "mailto:", "#")):
        return None

    parsed = urllib.parse.urlparse(raw)

    # Resolve relative URLs against the page they were found on
    if not parsed.scheme:
        raw = urllib.parse.urljoin(page_url, raw)
        parsed = urllib.parse.urlparse(raw)

    # Reject external hosts
    host = urllib.parse.urlparse(base).netloc
    if parsed.netloc and parsed.netloc != host:
        return None

    # Strip pure cache-buster query strings (all digits/hex, ≥ 10 chars)
    qs = parsed.query
    if qs and re.fullmatch(r"[0-9a-f]{10,}", qs, re.IGNORECASE):
        qs = ""

    canonical = urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, "", qs, "")
    )
    return canonical


def url_key(url: str) -> str:
    """
    Deduplication key: path only (no query, no fragment).
    Two URLs that differ only in cache-buster query params are treated as
    the same resource for the purpose of 'have we visited this?'.
    """
    p = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse((p.scheme, p.netloc, p.path, "", "", ""))


def url_to_local_path(url: str, output_dir: Path) -> Path:
    """
    Map an absolute URL to a local file-system path inside *output_dir*,
    mirroring the server's directory structure exactly.

    /index.asp               → <output>/index.asp
    /Cuscss/login.css        → <output>/Cuscss/login.css
    /                        → <output>/index.html
    /html/ssmp/              → <output>/html/ssmp/index.html
    """
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.lstrip("/")

    if not path:
        path = "index.html"
    elif path.endswith("/"):
        path += "index.html"

    return output_dir / Path(path)


# ---------------------------------------------------------------------------
# Deep link / path extraction
# ---------------------------------------------------------------------------

# ---- CSS ----
_CSS_URL_RE = re.compile(r"""url\(\s*['"]?([^)'">\s]+)['"]?\s*\)""", re.I)
_CSS_IMPORT_RE = re.compile(r"""@import\s+['"]([^'"]+)['"]""", re.I)


def _extract_css_urls(css: str, page_url: str, base: str) -> set[str]:
    found: set[str] = set()
    for pat in (_CSS_URL_RE, _CSS_IMPORT_RE):
        for m in pat.finditer(css):
            n = normalise_url(m.group(1), page_url, base)
            if n:
                found.add(n)
    return found


# ---- JavaScript deep extraction ----

# window.location = "..." or window.location.href = "..."
_WIN_LOC_RE = re.compile(
    r"""(?:window\.location(?:\.href)?|location\.href)\s*=\s*['"]([^'"]+)['"]""",
    re.I,
)

# Form.setAction('/some/path.cgi?params')  –  router-specific helper
_FORM_ACTION_RE = re.compile(
    r"""\.setAction\s*\(\s*['"]([^'"]+)['"]""",
    re.I,
)

# $.ajax({ url: '/path', ... }) — both with and without quotes around key
_AJAX_URL_RE = re.compile(
    r"""(?:['"]url['"]\s*:|url\s*:)\s*['"]([^'"]+)['"]""",
    re.I,
)

# document.write('<tag src="/path/to/file.js">') — extract nested markup
_DOC_WRITE_RE = re.compile(
    r"""document\.write\s*\(\s*['"](.+?)['"]""",
    re.I | re.DOTALL,
)

# RequestFile=login.asp embedded in CGI query strings
_REQUEST_FILE_RE = re.compile(
    r"""RequestFile=([^&'">\s]+)""",
    re.I,
)

# All root-relative quoted path strings: '/anything/here'
_ABS_QUOTED_PATH_RE = re.compile(
    r"""['"](/[a-zA-Z0-9_./%?&=+\-#]+)['"]""",
    re.I,
)

# Relative paths with a known web extension: 'some/page.asp'
_REL_EXT_PATH_RE = re.compile(
    r"""['"]([a-zA-Z0-9_\-./]+\.(?:asp|html|htm|cgi|js|css|png|jpg|jpeg|gif|ico|svg|json|xml|woff2?|ttf|eot|otf|bmp|webp))['"]""",
    re.I,
)


def _extract_js_paths(js: str, page_url: str, base: str) -> set[str]:
    """Extract every URL/path reference from JavaScript source."""
    found: set[str] = set()

    def _add(raw: str) -> None:
        n = normalise_url(raw.strip(), page_url, base)
        if n:
            found.add(n)

    for pat in (_WIN_LOC_RE, _FORM_ACTION_RE, _AJAX_URL_RE):
        for m in pat.finditer(js):
            _add(m.group(1))

    # document.write – treat written markup as HTML to extract src/href
    for m in _DOC_WRITE_RE.finditer(js):
        snippet = m.group(1).replace("\\'", "'").replace('\\"', '"')
        found |= _extract_html_attrs(snippet, page_url, base)

    # RequestFile= in any CGI action string
    for m in _REQUEST_FILE_RE.finditer(js):
        val = m.group(1)
        # May be absolute or just a filename like 'login.asp'
        if not val.startswith("/"):
            val = "/" + val
        _add(val)

    # All root-relative quoted strings
    for m in _ABS_QUOTED_PATH_RE.finditer(js):
        _add(m.group(1))

    # Relative paths with known extensions
    for m in _REL_EXT_PATH_RE.finditer(js):
        _add(m.group(1))

    return found


def _extract_html_attrs(html: str, page_url: str, base: str) -> set[str]:
    """
    Use BeautifulSoup to extract every resource URL from HTML/ASP content.
    Also parse inline <style> blocks and <script> blocks.
    """
    found: set[str] = set()

    def _add(raw: str) -> None:
        n = normalise_url(raw.strip(), page_url, base)
        if n:
            found.add(n)

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return found

    # --- Standard tag attributes ---
    attr_map = {
        "a":       ["href"],
        "link":    ["href"],
        "script":  ["src"],
        "img":     ["src", "data-src"],
        "source":  ["src", "srcset"],
        "iframe":  ["src"],
        "frame":   ["src"],
        "form":    ["action"],
        "input":   ["src"],
        "body":    ["background"],
        "meta":    [],         # handled below for http-equiv=refresh
        "object":  ["data"],
        "embed":   ["src"],
        "audio":   ["src"],
        "video":   ["src", "poster"],
        "track":   ["src"],
    }
    for tag, attrs in attr_map.items():
        for el in soup.find_all(tag):
            for attr in attrs:
                val = el.get(attr)
                if val:
                    _add(val)
            # meta http-equiv="refresh" content="0;url=/page.asp"
            if tag == "meta":
                content = el.get("content", "")
                m = re.search(r"url=([^\s;\"']+)", content, re.I)
                if m:
                    _add(m.group(1))

    # --- Inline <style> blocks ---
    for style_el in soup.find_all("style"):
        found |= _extract_css_urls(style_el.get_text(), page_url, base)

    # --- Inline <script> blocks ---
    for script_el in soup.find_all("script"):
        if not script_el.get("src"):
            found |= _extract_js_paths(script_el.get_text(), page_url, base)

    return found


def extract_links(
    content: bytes | str,
    content_type: str,
    url: str,
    base: str,
) -> set[str]:
    """
    Master link-extraction dispatcher.  Returns a set of absolute URLs found
    in *content*, parsed according to *content_type*.

    ASP files are always treated as HTML regardless of the Content-Type header.
    """
    found: set[str] = set()
    ct = content_type.split(";")[0].strip().lower()

    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")

    parsed_url = urllib.parse.urlparse(url)
    is_asp = parsed_url.path.lower().endswith(".asp")

    if ct in ("text/html", "application/xhtml+xml") or is_asp:
        found |= _extract_html_attrs(content, url, base)
        # Also run JS extractor over the raw text to catch anything BeautifulSoup
        # might miss (e.g. dynamically constructed strings outside <script> tags)
        found |= _extract_js_paths(content, url, base)

    elif ct in ("application/javascript", "text/javascript", "text/plain"):
        found |= _extract_js_paths(content, url, base)

    elif ct == "text/css":
        found |= _extract_css_urls(content, url, base)

    return found


# ---------------------------------------------------------------------------
# File saver
# ---------------------------------------------------------------------------

def save_file(local_path: Path, content: bytes) -> None:
    """Write *content* to *local_path*, creating all parent directories."""
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_bytes(content)
    log.debug("Saved → %s (%d bytes)", local_path, len(content))


# ---------------------------------------------------------------------------
# Seed paths – all known HG8145V5 admin page paths
# ---------------------------------------------------------------------------
# These are used to prime the BFS queue before the automatic crawler starts.
# The crawler will discover additional URLs on its own; these seeds ensure that
# pages which are not linked from other pages are still reached.
SEED_PATHS: list[str] = [
    # Entry points (NOT "/" – the root always returns the login form HTML,
    # even when authenticated; start from the authenticated admin pages instead)
    "/index.asp",
    "/login.asp",
    "/main.asp",
    "/main.html",
    "/frame.asp",

    # ASP helper endpoints
    "/asp/GetRandCount.asp",
    "/asp/GetRandInfo.asp",
    "/asp/CheckPwdNotLogin.asp",

    # Top-level status / info pages (common on HG8145 series)
    "/html/ssmp/home.asp",
    "/html/ssmp/status.asp",
    "/html/ssmp/internet.asp",
    "/html/ssmp/wan_info.asp",
    "/html/ssmp/wlan.asp",
    "/html/ssmp/wlan_basic.asp",
    "/html/ssmp/wlan_security.asp",
    "/html/ssmp/wlan_advanced.asp",
    "/html/ssmp/wlan_wds.asp",
    "/html/ssmp/wlan_wps.asp",
    "/html/ssmp/wlan_station.asp",
    "/html/ssmp/lan.asp",
    "/html/ssmp/lan_dhcp.asp",
    "/html/ssmp/lan_static.asp",
    "/html/ssmp/dhcp.asp",
    "/html/ssmp/security.asp",
    "/html/ssmp/firewall.asp",
    "/html/ssmp/nat.asp",
    "/html/ssmp/port_forward.asp",
    "/html/ssmp/port_trigger.asp",
    "/html/ssmp/alg.asp",
    "/html/ssmp/dmz.asp",
    "/html/ssmp/qos.asp",
    "/html/ssmp/route.asp",
    "/html/ssmp/dns.asp",
    "/html/ssmp/ddns.asp",
    "/html/ssmp/upnp.asp",
    "/html/ssmp/vpn.asp",
    "/html/ssmp/tr069.asp",
    "/html/ssmp/system.asp",
    "/html/ssmp/ntp.asp",
    "/html/ssmp/log.asp",
    "/html/ssmp/upgrade.asp",
    "/html/ssmp/backup.asp",
    "/html/ssmp/reboot.asp",
    "/html/ssmp/user_info.asp",
    "/html/ssmp/diagnosis.asp",
    "/html/ssmp/voice.asp",
    "/html/ssmp/pon.asp",
    "/html/ssmp/ipv6.asp",
    "/html/ssmp/multicast.asp",

    # Frame / navigation shell pages
    "/html/top.asp",
    "/html/left.asp",
    "/html/right.asp",
    "/html/bottom.asp",
    "/html/index.asp",
    "/html/menu.asp",
    "/html/frame.asp",

    # Core JavaScript libraries (parsing these reveals more paths)
    "/resource/common/md5.js",
    "/resource/common/util.js",
    "/resource/common/RndSecurityFormat.js",
    "/resource/common/safelogin.js",
    "/resource/common/jquery.min.js",
    "/resource/common/crypto-js.js",

    # Localisation / string resources
    "/frameaspdes/english/ssmpdes.js",

    # CSS
    "/Cuscss/login.css",
    "/Cuscss/english/frame.css",

    # Images / icons
    "/images/hwlogo.ico",
    "/images/hwlogo.png",
    "/images/hwlogo_cyta.jpg",
]


# ---------------------------------------------------------------------------
# Core downloader
# ---------------------------------------------------------------------------

class Crawler:
    """
    BFS crawler that:
      • maintains an authenticated session with automatic re-login
      • de-duplicates URLs by path (ignoring cache-buster query strings)
      • extracts links exhaustively from HTML/ASP/JS/CSS responses
      • saves every response to the local output directory tree
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        output_dir: Path,
        verify_ssl: bool = True,
        force: bool = False,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.output_dir = output_dir
        self.base = base_url(host)
        self.force = force  # when True, re-download even if the file exists on disk
        self.session = build_session(verify_ssl=verify_ssl)

        # Set of URL keys (path-only) that have already been processed
        self._visited: set[str] = set()
        # BFS queue of full absolute URLs (may include query strings)
        self._queue: deque[str] = deque()
        # Re-login attempt counter – reset to 0 after each successful response
        self._relogin_count = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> None:
        log.info("Output directory : %s", self.output_dir.resolve())
        log.info("Target router    : %s", self.base)
        log.info("Username         : %s", self.username)

        post_login_url = login(self.session, self.host, self.username, self.password)
        if not post_login_url:
            sys.exit(1)

        # Set Referer to the post-login page so all subsequent requests
        # appear to come from within the admin interface.  Many Huawei routers
        # enforce a Referer check on admin ASP pages and return 403 without it.
        self.session.headers["Referer"] = post_login_url
        log.debug("Referer set to: %s", post_login_url)

        # Resume: scan previously downloaded files so we don't re-fetch them
        # and so we can discover links that were not followed before.
        if not self.force:
            n = self._resume_from_disk()
            if n:
                log.info("Resume: %d existing file(s) loaded from disk.", n)

        # Seed the queue: start with the authenticated home page, then all
        # known admin page paths.
        self._enqueue(post_login_url)
        for path in SEED_PATHS:
            self._enqueue(self.base + path)

        # Exhaust the queue
        while self._queue:
            url = self._queue.popleft()
            self._fetch_and_process(url)

        log.info(
            "Crawl complete. %d unique URLs visited.", len(self._visited)
        )
        log.info("Files saved in: %s", self.output_dir.resolve())

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    # Content-type to use when parsing a file loaded from disk.
    # Defined once here and shared by _resume_from_disk and _parse_local_file.
    _DISK_CT: dict[str, str] = {
        ".asp":  "text/html",
        ".html": "text/html",
        ".htm":  "text/html",
        ".js":   "application/javascript",
        ".css":  "text/css",
    }

    def _parse_local_file(self, local_path: Path, url: str) -> int:
        """
        Read *local_path* from disk, extract links, and enqueue any that have
        not been visited yet.  Returns the number of new URLs enqueued.
        Only files with an extension in *_DISK_CT* are parsed; binary/unknown
        file types are silently skipped.
        """
        ct = self._DISK_CT.get(local_path.suffix.lower())
        if ct is None:
            return 0

        try:
            content = local_path.read_bytes()
        except OSError as exc:
            log.debug("Could not read local file %s for link extraction: %s",
                      local_path, exc)
            return 0

        added = 0
        for link in extract_links(content, ct, url, self.base):
            k = url_key(link)
            if k not in self._visited:
                self._queue.append(link)
                added += 1
        return added

    def _resume_from_disk(self) -> int:
        """
        Scan *output_dir* for previously downloaded files.

        For each file found:
          - its URL key is added to *_visited* so it won't be re-downloaded.
          - if it is an HTML/ASP/JS/CSS file, its content is parsed and any
            newly discovered links are added to the crawl queue.

        Returns the number of local files found.
        """
        if not self.output_dir.exists():
            return 0

        count = 0
        for local_path in sorted(self.output_dir.rglob("*")):
            if not local_path.is_file():
                continue

            # Reconstruct the server URL from the relative path on disk
            rel = local_path.relative_to(self.output_dir)
            path_str = "/" + str(rel).replace("\\", "/")

            # Reverse the "directory → index.html" mapping applied when saving
            if path_str == "/index.html":
                path_str = "/"
            elif path_str.endswith("/index.html"):
                path_str = path_str[: -len("index.html")]

            url = self.base + path_str
            key = url_key(url)

            if key in self._visited:
                continue
            self._visited.add(key)
            count += 1
            log.debug("Resume: existing file %s → %s", local_path.name, url)

            self._parse_local_file(local_path, url)

        return count

    def _enqueue(self, url: str) -> None:
        """Add *url* to the queue if it has not been visited yet."""
        key = url_key(url)
        if key not in self._visited:
            self._queue.append(url)

    def _fetch_and_process(self, url: str) -> None:
        key = url_key(url)
        if key in self._visited:
            return
        self._visited.add(key)

        # Never crawl write-action endpoints (logout terminates the session;
        # reboot/reset/factory would change the router's state).
        if _BLOCKED_PATH_RE.search(urllib.parse.urlparse(url).path):
            log.debug("Blocked write-action URL, skipping: %s", url)
            return

        local = url_to_local_path(url, self.output_dir)

        # ----------------------------------------------------------------
        # Skip re-downloading files that already exist on disk.
        # Still parse the cached copy so we can discover more links.
        # Use --force to override and re-download everything.
        # ----------------------------------------------------------------
        if not self.force and local.exists():
            log.info("[SKIP] Already on disk: %s", url)
            added = self._parse_local_file(local, url)
            if added:
                log.debug("  +%d new URLs from cached %s", added, local.name)
            return

        log.info("[%d queued] GET %s", len(self._queue), url)

        try:
            resp = self.session.get(
                url, timeout=REQUEST_TIMEOUT, allow_redirects=True
            )
        except requests.RequestException as exc:
            log.warning("Request failed for %s – %s", url, exc)
            return

        # --- Session expiry detection & recovery ---
        if resp.status_code == 401 or is_session_expired(resp):
            log.warning("Session expired at %s – attempting re-login", url)
            if self._relogin_count < MAX_RELOGIN_ATTEMPTS:
                self._relogin_count += 1
                # Clear old auth cookies before re-logging in
                self.session.cookies.clear()
                new_login_url = login(
                    self.session, self.host, self.username, self.password
                )
                if new_login_url:
                    log.info("Re-login successful (attempt %d)", self._relogin_count)
                    # Update Referer to the new post-login page
                    self.session.headers["Referer"] = new_login_url
                    # Remove from visited so we retry this URL
                    self._visited.discard(key)
                    self._queue.appendleft(url)
                    return
            log.error("Could not recover session after %d attempts", self._relogin_count)
            return

        if not resp.ok:
            log.warning("HTTP %s for %s – skipping", resp.status_code, url)
            return

        # Successful response – reset the re-login counter so each new
        # session expiry gets MAX_RELOGIN_ATTEMPTS fresh attempts.
        self._relogin_count = 0

        content_type = resp.headers.get("Content-Type", "application/octet-stream")
        content = resp.content

        log.debug(
            "  ← HTTP %s  Content-Type: %s  %d bytes",
            resp.status_code,
            content_type,
            len(content),
        )
        log.debug("  Active cookies: %s", list(self.session.cookies.keys()))

        # Save to disk
        save_file(local, content)

        # Parse for further links
        ct = content_type.split(";")[0].strip().lower()
        is_asp = urllib.parse.urlparse(url).path.lower().endswith(".asp")

        if ct in CRAWLABLE_TYPES or is_asp:
            new_links = extract_links(content, content_type, url, self.base)
            added = 0
            for link in new_links:
                k = url_key(link)
                if k not in self._visited:
                    self._queue.append(link)
                    added += 1
            if added:
                log.debug("  +%d new URLs enqueued", added)

        time.sleep(DELAY_BETWEEN_REQUESTS)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Huawei HG8145V5 router admin-panel crawler – "
                    "exhaustively downloads all pages and assets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Password can also be provided via the ROUTER_PASSWORD env var.\n"
            "If the password is not supplied and not in the environment, "
            "you will be prompted for it."
        ),
    )
    parser.add_argument(
        "--host", default=DEFAULT_HOST,
        help=f"Router IP address (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--user", default=DEFAULT_USER,
        help=f"Admin username (default: {DEFAULT_USER})",
    )
    parser.add_argument(
        "--password", default=DEFAULT_PASSWORD,
        help="Admin password (overrides ROUTER_PASSWORD env var)",
    )
    parser.add_argument(
        "--output", default=DEFAULT_OUTPUT,
        help=f"Output directory (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--no-verify-ssl", dest="verify_ssl", action="store_false", default=True,
        help="Disable TLS certificate verification (use for self-signed certs)",
    )
    parser.add_argument(
        "--force", action="store_true", default=False,
        help="Re-download files even if they already exist on disk "
             "(default: skip existing files and parse them for new links)",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable verbose debug logging",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)
        logging.getLogger("urllib3").setLevel(logging.DEBUG)

    if not args.verify_ssl:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
        log.warning("TLS certificate verification is DISABLED (--no-verify-ssl)")

    if not args.password:
        import getpass
        args.password = getpass.getpass("Router password: ")

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    crawler = Crawler(
        host=args.host,
        username=args.user,
        password=args.password,
        output_dir=output_dir,
        verify_ssl=args.verify_ssl,
        force=args.force,
    )
    crawler.run()


if __name__ == "__main__":
    main()
