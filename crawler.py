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
import hashlib
import json
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

try:
    import colorlog
    _COLORLOG_AVAILABLE = True
except ImportError:
    _COLORLOG_AVAILABLE = False

try:
    from tqdm import tqdm as _tqdm
    _TQDM_AVAILABLE = True
except ImportError:
    _TQDM_AVAILABLE = False

# ---------------------------------------------------------------------------
# Logging – coloured output when colorlog is available
# ---------------------------------------------------------------------------
log = logging.getLogger("hg8145v5-crawler")


def _setup_logging(debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    log.setLevel(level)
    log.handlers.clear()

    if _COLORLOG_AVAILABLE:
        handler = colorlog.StreamHandler()
        handler.setFormatter(colorlog.ColoredFormatter(
            "%(log_color)s%(asctime)s [%(levelname)s]%(reset)s %(message)s",
            datefmt="%H:%M:%S",
            log_colors={
                "DEBUG":    "cyan",
                "INFO":     "green",
                "WARNING":  "yellow",
                "ERROR":    "red",
                "CRITICAL": "bold_red",
            },
        ))
    else:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"
        ))
    log.addHandler(handler)

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Session bootstrap
# ---------------------------------------------------------------------------

try:
    import lxml  # noqa: F401 – used as BeautifulSoup parser backend
    _BS4_PARSER = "lxml"
except ImportError:
    _BS4_PARSER = "html.parser"


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
    Used when CfgMode != 'DVODACOM2WIFI'.
    """
    return base64.b64encode(password.encode("utf-8")).decode("ascii")


def pbkdf2_sha256_password(password: str, salt: str, iterations: int) -> str:
    """
    Replicate the loginWithSha256() function from index.asp (CfgMode DVODACOM2WIFI):

      1. PBKDF2(password, salt, {keySize:8, hasher:SHA256, iterations:N})
         → 32 bytes (keySize 8 = 8 × 32-bit words)
      2. CryptoJS.SHA256(pbkdf2.toString())  where .toString() gives hex
         → SHA-256 over the UTF-8 bytes of the PBKDF2 hex string
      3. Base64(sha256_hex.encode('utf-8'))  – CryptoJS Utf8.parse + Base64.stringify
    """
    import hashlib as _hashlib
    dk = _hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
        dklen=32,   # keySize:8 means 8 * 32-bit words = 32 bytes
    )
    pbkdf2_hex = dk.hex()                                     # step 1 → hex string
    sha256_hex = _hashlib.sha256(pbkdf2_hex.encode("utf-8")).hexdigest()  # step 2
    return base64.b64encode(sha256_hex.encode("utf-8")).decode("ascii")   # step 3


def detect_login_mode(session: requests.Session, host: str) -> str:
    """
    Fetch /index.asp and parse the embedded JavaScript to determine which
    login method the router uses.

    Returns the CfgMode string (e.g. 'MEGACABLE2', 'DVODACOM2WIFI', …).
    Returns an empty string on failure (safe fallback = base64 path).
    """
    try:
        resp = session.get(base_url(host) + LOGIN_PAGE, timeout=REQUEST_TIMEOUT)
        cfg_mode = re.search(r"""var\s+CfgMode\s*=\s*['"]([^'"]+)['"]""", resp.text)
        return cfg_mode.group(1) if cfg_mode else ""
    except Exception:
        return ""


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
    Authenticate against the HG8145V5 admin interface.

    Auto-detects the login method from the login page:
      • Most configs (e.g. MEGACABLE2):
          GET /index.asp → POST /asp/GetRandCount.asp for CSRF token
          POST /login.cgi  UserName / base64(Password) / Language / x.X_HW_Token
      • CfgMode == 'DVODACOM2WIFI':
          POST /asp/GetRandInfo.asp  to get [token, salt, iterations]
          PBKDF2+SHA256(password, salt, iterations) → base64
          POST /login.cgi  UserName / encoded_password / Language / x.X_HW_Token

    Returns the post-login redirect URL (the admin home page) on success,
    or None on failure.  The URL is used as a seed and as the Referer header.
    """
    # Step 1 – load login page; also detect router config mode
    cfg_mode = detect_login_mode(session, host)
    log.debug("Router CfgMode: %r", cfg_mode)

    log.debug("Cookies after GET /index.asp: %s", dict(session.cookies))

    use_sha256 = cfg_mode.upper() == "DVODACOM2WIFI"

    if use_sha256:
        # --- PBKDF2+SHA256 path (index.asp loginWithSha256) ---
        # POST /asp/GetRandInfo.asp -> dealDataWithFun returns [token, salt, iters]
        try:
            info_resp = session.post(
                base_url(host) + RAND_INFO_URL + "?&1=1",
                data={"Username": username},
                timeout=REQUEST_TIMEOUT,
            )
            info_resp.raise_for_status()
            # Response is a JS function-call string like:
            #   function(){return ['TOKEN','SALT','1000'];}
            # Extract the array elements.
            m = re.search(r"\[([^\]]+)\]", info_resp.text)
            if not m:
                log.error("Could not parse GetRandInfo response: %s", info_resp.text[:120])
                return None
            parts = [p.strip().strip("'\"") for p in m.group(1).split(",")]
            if len(parts) < 3:
                log.error("Unexpected GetRandInfo parts: %s", parts)
                return None
            token, salt, iterations_str = parts[0], parts[1], parts[2]
            iterations = int(iterations_str)
            encoded_pw = pbkdf2_sha256_password(password, salt, iterations)
            log.debug("PBKDF2 login: token=%s salt=%s iters=%d", token, salt, iterations)
        except (requests.RequestException, ValueError) as exc:
            log.error("GetRandInfo failed: %s", exc)
            return None
    else:
        # --- Base64 path (standard for MEGACABLE2 and most other configs) ---
        # Set the pre-login cookie to mimic what the login page JS does:
        #   var cookie2 = "Cookie=body:Language:english:id=-1;path=/";
        #   document.cookie = cookie2;
        # NOTE: in document.cookie syntax ';path=/' is a COOKIE ATTRIBUTE,
        # not part of the value.  We specify it via the path= kwarg here so
        # the router receives the correct value: 'body:Language:english:id=-1'.
        session.cookies.set(
            "Cookie",
            "body:Language:english:id=-1",
            domain=host,
            path="/",
        )
        try:
            token = get_rand_token(session, host)
        except requests.RequestException as exc:
            log.error("Failed to get auth token: %s", exc)
            return None
        encoded_pw = b64encode_password(password)

    # Step 3 – submit credentials (common to both paths)
    payload = {
        "UserName": username,
        "PassWord": encoded_pw,
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
            "Check your credentials or try --debug for more info."
        )
        return None

    # The router's login.cgi always returns HTTP 200 with a *JavaScript*
    # redirect (e.g. "var pageName = '/'; top.location.replace(pageName);").
    # requests does NOT execute JavaScript, so resp.url stays at login.cgi
    # and we would wrongly set Referer = login.cgi for all admin pages
    # (causing 403 on every admin ASP page).
    # We must manually follow the JS redirect to get the real admin home URL.
    redirect_path = "/"
    m_js = re.search(
        r"""var\s+pageName\s*=\s*['"]([^'"]+)['"]|top\.location(?:\.replace)?\s*\(\s*['"]([^'"]+)['"]\s*\)""",
        resp.text,
        re.I,
    )
    if m_js:
        redirect_path = next(
            (g for g in (m_js.group(1), m_js.group(2)) if g is not None and g),
            "/",
        )

    redirect_url = urllib.parse.urljoin(base_url(host), redirect_path)
    try:
        follow_resp = session.get(
            redirect_url, timeout=REQUEST_TIMEOUT, allow_redirects=True
        )
        post_login_url = follow_resp.url
        log.debug("Followed JS redirect → %s", post_login_url)
    except requests.RequestException as exc:
        log.debug("Could not follow post-login redirect to %s: %s", redirect_url, exc)
        post_login_url = redirect_url

    log.info(
        "Login successful (HTTP %s, method=%s). Admin home: %s. "
        "Active cookies: %s",
        resp.status_code,
        "PBKDF2" if use_sha256 else "base64",
        post_login_url,
        list(session.cookies.keys()),
    )
    log.debug("Cookie values after login: %s", dict(session.cookies))
    return post_login_url


def is_session_expired(resp: requests.Response) -> bool:
    """
    Return True only when the router has genuinely redirected to the login form.

    Avoids two classes of false positives that caused session-expiry loops:
      * URL-based false positive: 'login' in url matches /Cuscss/login.css, safelogin.js, etc.
        -> now checks only the specific login-page paths /index.asp and /login.asp.
      * Body-based false positive: JS files contain login marker strings as DOM element IDs
        (e.g. document.getElementById('txt_Password')), CSS contains .loginbutton.
        -> now ignores non-HTML content types and requires ALL markers together.

    Also detects the post-logout state: logout.html resets the session cookie to
    'Cookie=default' (document.cookie = 'Cookie=default;path=/') which is a clear
    sign the session has been terminated.
    """
    cookie_val = resp.cookies.get("Cookie", "")
    if cookie_val.lower() == "default":
        return True

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


# ---- JSON ----

def _extract_json_paths(text: str, page_url: str, base: str) -> set[str]:
    """
    Parse JSON responses and extract any string values that look like URL paths.
    Handles both proper JSON and JS-style objects returned by Huawei's getajax.cgi.
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
            elif isinstance(item, str) and item.startswith("/"):
                n = normalise_url(item, page_url, base)
                if n:
                    found.add(n)
    except (json.JSONDecodeError, ValueError):
        pass
    return found


# ---- JavaScript deep extraction ----

# window.location = "..." or window.location.href = "..."
_WIN_LOC_RE = re.compile(
    r"""(?:window\.location(?:\.href)?|location\.href|location\.replace)\s*[=(]\s*['"`]([^'"`\n]+)['"`]""",
    re.I,
)

# Form.setAction('/some/path.cgi?params')  –  router-specific helper
_FORM_ACTION_RE = re.compile(
    r"""\.setAction\s*\(\s*['"`]([^'"`\n]+)['"`]""",
    re.I,
)

# $.ajax({ url: '/path', ... }) / fetch('/path') / axios.get('/path')
_AJAX_URL_RE = re.compile(
    r"""(?:['"]url['"]\s*:|url\s*:|fetch\s*\(|axios\.(?:get|post)\s*\()\s*['"`]([^'"`\n]+)['"`]""",
    re.I,
)

# document.write('<tag src="/path/to/file.js">') — extract nested markup
_DOC_WRITE_RE = re.compile(
    r"""document\.write\s*\(\s*['"`](.+?)['"`]""",
    re.I | re.DOTALL,
)

# RequestFile=login.asp embedded in CGI query strings (Huawei-specific)
_REQUEST_FILE_RE = re.compile(
    r"""RequestFile=([^&'">\s\n]+)""",
    re.I,
)

# All root-relative quoted path strings: '/anything/here'
_ABS_QUOTED_PATH_RE = re.compile(
    r"""['"`](/[a-zA-Z0-9_./%?&=+\-#][^'"`\n]{0,200})['"`]""",
    re.I,
)

# Relative paths with a known web extension (catches 'wlan.asp', '../images/x.jpg', etc.)
_REL_EXT_PATH_RE = re.compile(
    r"""['"`]([.]{0,2}/[a-zA-Z0-9_\-./]+\.(?:asp|html|htm|cgi|js|css|png|jpg|jpeg|gif|ico|svg|json|xml|woff2?|ttf|eot|otf|bmp|webp))['"`]""",
    re.I,
)

# Template literals that contain only a simple path: `/html/ssmp/${name}.asp`
# Extracts the static prefix up to the first interpolation marker.
_TEMPLATE_PATH_RE = re.compile(
    r"""`(/[a-zA-Z0-9_/.-]+(?:\$\{[^}]+\}[a-zA-Z0-9_/.-]*)*)` """,
    re.I,
)

# JS object / array literal paths:  { url: '/path' }  or  ['/path1', '/path2']
_OBJ_PROP_PATH_RE = re.compile(
    r"""[\[,{]\s*['"`](/[a-zA-Z0-9_./%?&=+\-][^'"`\n]{0,150})['"`]\s*[,\]}]""",
    re.I,
)

# var/let/const  varName = '/path'  assignments
_VAR_ASSIGN_RE = re.compile(
    r"""(?:var|let|const)\s+\w+\s*=\s*['"`](/[a-zA-Z0-9_./%?&=+\-#][^'"`\n]{0,200})['"`]""",
    re.I,
)

# Huawei-specific: string concatenation   '/html/ssmp/' + pageName + '.asp'
# Extracts the static prefix to queue as a candidate
_CONCAT_PREFIX_RE = re.compile(
    r"""['"`](/html/[a-zA-Z0-9_/]+/)['"`]\s*\+""",
    re.I,
)


def _extract_js_paths(js: str, page_url: str, base: str) -> set[str]:
    """
    Exhaustively extract every URL/path reference from JavaScript source.

    Uses many overlapping patterns to maximise discovery:
      • Explicit navigation (window.location, Form.setAction, fetch, $.ajax)
      • All root-relative quoted strings
      • Relative paths with known web extensions
      • Template literals
      • Object/array literals containing paths
      • Variable assignments
      • Huawei-specific concatenation prefixes
      • RequestFile= CGI parameter values
      • document.write() nested markup
    """
    found: set[str] = set()

    def _add(raw: str) -> None:
        # Skip strings that still contain template-literal interpolation markers
        # or embedded quote characters – these are not valid URL paths but
        # fragments of JS expressions captured by the broader regexes.
        # (Legitimate URL query strings use percent-encoding, not raw quotes.)
        if "${" in raw or "'" in raw or '"' in raw:
            return
        n = normalise_url(raw.strip(), page_url, base)
        if n:
            found.add(n)

    # All targeted patterns
    for pat in (
        _WIN_LOC_RE,
        _FORM_ACTION_RE,
        _AJAX_URL_RE,
        _ABS_QUOTED_PATH_RE,
        _REL_EXT_PATH_RE,
        _OBJ_PROP_PATH_RE,
        _VAR_ASSIGN_RE,
        _CONCAT_PREFIX_RE,
    ):
        for m in pat.finditer(js):
            _add(m.group(1))

    # Template literal – queue the static prefix as a directory hint
    for m in _TEMPLATE_PATH_RE.finditer(js):
        raw = re.sub(r"\$\{[^}]+\}", "", m.group(1))  # strip interpolations
        _add(raw)

    # document.write – treat written markup as HTML to extract src/href
    for m in _DOC_WRITE_RE.finditer(js):
        snippet = m.group(1).replace("\\'", "'").replace('\\"', '"')
        found |= _extract_html_attrs(snippet, page_url, base)

    # RequestFile= in any CGI action string
    for m in _REQUEST_FILE_RE.finditer(js):
        val = m.group(1)
        if not val.startswith("/"):
            val = "/" + val
        _add(val)

    return found


def _extract_html_attrs(html: str, page_url: str, base: str) -> set[str]:
    """
    Use BeautifulSoup (with lxml when available) to extract every resource
    URL from HTML/ASP content.  Also parses inline <style> and <script>.
    """
    found: set[str] = set()

    def _add(raw: str) -> None:
        n = normalise_url(raw.strip(), page_url, base)
        if n:
            found.add(n)

    try:
        soup = BeautifulSoup(html, _BS4_PARSER)
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


def save_file(local_path: Path, content: bytes) -> None:
    """Write *content* to *local_path*, creating all parent directories."""
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_bytes(content)
    log.debug("Saved → %s (%d bytes)", local_path, len(content))


def content_hash(data: bytes) -> str:
    """Return a short SHA-256 hex digest for deduplication."""
    return hashlib.sha256(data).hexdigest()[:16]


def smart_local_path(
    url: str,
    output_dir: Path,
    content_type: str,
    content_disposition: str = "",
) -> Path:
    """
    Determine the local save path for a response.

    Priority:
      1. filename= from Content-Disposition header
      2. filename from URL path
      3. If URL path has no extension but Content-Type suggests one, append it
      4. Extensionless URLs become <name>.html when CT is text/html
    """
    # Content-Disposition: attachment; filename="foo.bin"
    if content_disposition:
        m = re.search(r'filename\s*=\s*["\']?([^\s"\']+)', content_disposition, re.I)
        if m:
            fname = m.group(1).strip()
            parsed = urllib.parse.urlparse(url)
            dir_part = Path(parsed.path.lstrip("/")).parent
            return output_dir / dir_part / fname

    parsed = urllib.parse.urlparse(url)
    path = parsed.path.lstrip("/")

    if not path:
        path = "index.html"
    elif path.endswith("/"):
        path += "index.html"
    else:
        # If no extension, try to derive one from Content-Type
        stem = Path(path)
        if not stem.suffix:
            ct = content_type.split(";")[0].strip().lower()
            ext_map = {
                "text/html":             ".html",
                "application/xhtml+xml": ".html",
                "text/css":              ".css",
                "application/javascript":".js",
                "text/javascript":       ".js",
                "application/json":      ".json",
                "text/xml":              ".xml",
                "application/xml":       ".xml",
                "image/png":             ".png",
                "image/jpeg":            ".jpg",
                "image/gif":             ".gif",
                "image/svg+xml":         ".svg",
                "image/x-icon":          ".ico",
                "image/vnd.microsoft.icon": ".ico",
            }
            if ct in ext_map:
                path += ext_map[ct]

    return output_dir / Path(path)


# ---------------------------------------------------------------------------
# Core BFS crawler
# ---------------------------------------------------------------------------

class Crawler:
    """
    Fully dynamic BFS crawler that discovers all router pages automatically.

    Key design decisions:
      • No hardcoded URL list – seeds only from the login page (/index.asp)
        and the post-login redirect URL.  Every other page is discovered by
        recursively extracting links from downloaded content.
      • Authenticated session with automatic re-login on expiry.
      • X_HW_Token maintained throughout the session; 403 responses are
        retried once with a fresh token appended as a query parameter.
      • Content-hash deduplication prevents saving the same bytes twice
        even if the router serves them under different URLs.
      • lxml-accelerated HTML parsing when the library is available.
      • tqdm live progress bar when the library is available.
      • Colored logging when colorlog is available.
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
        self.force = force
        self.session = build_session(verify_ssl=verify_ssl)

        self._visited:   set[str]   = set()   # URL keys already processed
        self._queue:     deque[str] = deque() # BFS queue (absolute URLs)
        self._hashes:    set[str]   = set()   # content hashes seen (dedup)
        self._relogin_count   = 0
        self._fetch_count     = 0
        self._current_token:  str | None = None   # latest X_HW_Token
        self._stats = {"ok": 0, "skip": 0, "err": 0, "dup": 0}

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

        # Set Referer to the router root ("/") for ALL subsequent requests.
        # Admin ASP pages are loaded inside the frameset at "/", so the router
        # expects Referer: http://192.168.100.1/ — not login.cgi.
        # Using login.cgi as Referer caused HTTP 403 on every admin page.
        self.session.headers["Referer"] = self.base + "/"

        # Fetch a fresh X_HW_Token right after login.
        # GetRandToken.asp also needs the correct Referer, which is now set.
        self._refresh_token()

        # Resume: scan previously downloaded files so we don't re-fetch them
        # and so we can discover links that were not followed before.
        if not self.force:
            n = self._resume_from_disk()
            if n:
                log.info("Resume: %d existing file(s) loaded from disk.", n)

        # --- Dynamic seeding ---
        # Seed from:
        #   1. "/" (admin frameset – contains <frame> refs to all admin pages)
        #   2. "/index.asp" (login page – contains ALL JS/CSS resource refs)
        #   3. post_login_url (wherever the router actually redirected after login)
        # Everything else is discovered by recursively following links.
        self._enqueue(self.base + "/")
        self._enqueue(self.base + "/index.asp")
        if post_login_url not in (self.base + "/", self.base + "/index.asp"):
            self._enqueue(post_login_url)

        log.info(
            "Seeding from / + /index.asp + post-login URL. Dynamic discovery begins.",
        )

        # Exhaust the queue with optional tqdm progress bar
        if _TQDM_AVAILABLE:
            self._run_with_progress()
        else:
            while self._queue:
                url = self._queue.popleft()
                self._fetch_and_process(url)

        log.info(
            "Crawl complete. visited=%d  ok=%d  skip=%d  dup=%d  err=%d",
            len(self._visited),
            self._stats["ok"],
            self._stats["skip"],
            self._stats["dup"],
            self._stats["err"],
        )
        log.info("Files saved in: %s", self.output_dir.resolve())

    def _run_with_progress(self) -> None:
        """BFS loop with a tqdm progress bar that tracks discovered vs visited."""
        bar = _tqdm(
            desc="Crawling",
            unit="URL",
            dynamic_ncols=True,
            bar_format="{l_bar}{bar}| {n}/{total} [{elapsed}<{remaining}] {postfix}",
        )
        total_seen = len(self._queue) + len(self._visited)
        bar.total = total_seen

        while self._queue:
            url = self._queue.popleft()
            prev_q = len(self._queue)
            self._fetch_and_process(url)
            new_items = len(self._queue) - prev_q
            if new_items > 0:
                bar.total += new_items
                total_seen += new_items
            bar.update(1)
            bar.set_postfix(
                queued=len(self._queue),
                ok=self._stats["ok"],
                err=self._stats["err"],
            )

        bar.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    _DISK_CT: dict[str, str] = {
        ".asp":  "text/html",
        ".html": "text/html",
        ".htm":  "text/html",
        ".js":   "application/javascript",
        ".css":  "text/css",
        ".json": "application/json",
        ".xml":  "application/xml",
    }

    def _parse_local_file(self, local_path: Path, url: str) -> int:
        """
        Read *local_path* from disk, extract links, and enqueue new ones.
        Returns the number of newly enqueued URLs.
        """
        ct = self._DISK_CT.get(local_path.suffix.lower())
        if ct is None:
            return 0
        try:
            content = local_path.read_bytes()
        except OSError as exc:
            log.debug("Could not read %s for link extraction: %s", local_path, exc)
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
        Scan *output_dir* for previously downloaded files, mark them visited,
        and extract any un-followed links from their content.
        """
        if not self.output_dir.exists():
            return 0
        count = 0
        for local_path in sorted(self.output_dir.rglob("*")):
            if not local_path.is_file():
                continue
            rel = local_path.relative_to(self.output_dir)
            path_str = "/" + str(rel).replace("\\", "/")
            if path_str == "/index.html":
                path_str = "/"
            elif path_str.endswith("/index.html"):
                path_str = path_str[:-len("index.html")]
            url = self.base + path_str
            key = url_key(url)
            if key in self._visited:
                continue
            self._visited.add(key)
            count += 1
            log.debug("Resume: %s → %s", local_path.name, url)
            self._parse_local_file(local_path, url)
        return count

    def _enqueue(self, url: str) -> None:
        """Add *url* to the queue if it has not been visited yet."""
        key = url_key(url)
        if key not in self._visited:
            self._queue.append(url)

    def _heartbeat(self) -> None:
        """
        POST to GetRandToken.asp to refresh both the session idle timer and
        our cached X_HW_Token.
        """
        self._refresh_token()

    def _refresh_token(self) -> None:
        """
        POST to /html/ssmp/common/GetRandToken.asp to get a fresh X_HW_Token.
        The token is stored in _current_token for use in 403 retries.
        Falls back silently if the endpoint is unavailable (e.g. not yet logged in).
        """
        try:
            resp = self.session.post(
                self.base + TOKEN_URL,
                timeout=REQUEST_TIMEOUT,
            )
            token = resp.text.strip()
            if token and len(token) >= 8:
                self._current_token = token
                log.debug("X_HW_Token refreshed: %s…", token[:12])
        except requests.RequestException as exc:
            log.debug("Token refresh failed (non-fatal): %s", exc)

    def _retry_with_token(self, url: str) -> requests.Response | None:
        """
        Retry a 403 request by appending a fresh X_HW_Token as a query
        parameter.  Returns the new response, or None if no token available.

        Some Huawei admin pages check for a valid X_HW_Token even in GET
        requests when accessed directly rather than through the frameset.
        """
        self._refresh_token()
        if not self._current_token:
            return None
        sep = "&" if "?" in url else "?"
        token_url = f"{url}{sep}x.X_HW_Token={self._current_token}"
        try:
            log.debug("403 retry with token: %s", token_url)
            return self.session.get(
                token_url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
        except requests.RequestException:
            return None

    def _fetch_and_process(self, url: str) -> None:
        key = url_key(url)
        if key in self._visited:
            return
        self._visited.add(key)

        # Never crawl write-action endpoints
        if _BLOCKED_PATH_RE.search(urllib.parse.urlparse(url).path):
            log.debug("Blocked write-action URL, skipping: %s", url)
            return

        local = smart_local_path(url, self.output_dir, "")

        # Skip already-downloaded files; parse them for new links
        if not self.force and local.exists() and local.stat().st_size > 0:
            log.info("[SKIP] Already on disk: %s", url)
            self._stats["skip"] += 1
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
            self._stats["err"] += 1
            return

        # --- Session expiry detection & recovery ---
        if resp.status_code == 401 or is_session_expired(resp):
            log.warning("Session expired at %s – attempting re-login", url)
            if self._relogin_count < MAX_RELOGIN_ATTEMPTS:
                self._relogin_count += 1
                self.session.cookies.clear()
                new_login_url = login(
                    self.session, self.host, self.username, self.password
                )
                if new_login_url:
                    log.info("Re-login successful (attempt %d)", self._relogin_count)
                    self.session.headers["Referer"] = new_login_url
                    self._refresh_token()
                    self._visited.discard(key)
                    self._queue.appendleft(url)
                    return
            log.error("Could not recover session after %d attempts", self._relogin_count)
            self._stats["err"] += 1
            return

        # --- 403 smart retry with X_HW_Token ---
        if resp.status_code == 403:
            log.debug("HTTP 403 for %s – retrying with token", url)
            retry = self._retry_with_token(url)
            if retry is not None and retry.ok:
                log.info("Token retry succeeded for %s", url)
                resp = retry
            else:
                log.warning("HTTP 403 for %s – skipping", url)
                self._stats["err"] += 1
                return

        if not resp.ok:
            log.warning("HTTP %s for %s – skipping", resp.status_code, url)
            self._stats["err"] += 1
            return

        # Successful response – reset the re-login counter
        self._relogin_count = 0
        self._fetch_count += 1
        if self._fetch_count % SESSION_HEARTBEAT_EVERY == 0:
            self._heartbeat()

        content_type = resp.headers.get("Content-Type", "application/octet-stream")
        content_disp  = resp.headers.get("Content-Disposition", "")
        content = resp.content

        log.debug(
            "  ← HTTP %s  CT: %s  %d bytes",
            resp.status_code, content_type, len(content),
        )

        # Content-hash deduplication: skip saving if we already have this
        # exact content (e.g. the same image served under two URLs).
        ch = content_hash(content)
        if ch in self._hashes:
            log.debug("  Duplicate content for %s – not saving again", url)
            self._stats["dup"] += 1
        else:
            self._hashes.add(ch)
            local = smart_local_path(url, self.output_dir, content_type, content_disp)
            save_file(local, content)
            self._stats["ok"] += 1

        # Extract links for further crawling
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

    _setup_logging(debug=args.debug)

    if args.debug:
        logging.getLogger("urllib3").setLevel(logging.DEBUG)

    if not args.verify_ssl:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
        log.warning("TLS certificate verification is DISABLED (--no-verify-ssl)")

    if not _TQDM_AVAILABLE:
        log.info("Tip: install tqdm for a live progress bar  (pip install tqdm)")
    if not _COLORLOG_AVAILABLE:
        log.info("Tip: install colorlog for colored output   (pip install colorlog)")

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
