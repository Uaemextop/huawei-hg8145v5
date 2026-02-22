#!/usr/bin/env python3
"""
Huawei HG8145V5 Router Web Crawler
====================================
Logs into the router admin panel at http://192.168.100.1 and downloads
all reachable pages and static assets (HTML/ASP, JS, CSS, images, etc.)
preserving the original directory structure for offline analysis.

Usage (Windows / Linux / macOS):
    pip install -r requirements.txt
    python crawler.py

Optional command-line overrides:
    python crawler.py --host 192.168.100.1 --user Mega_gpon \
        --password 796cce597901a5cf --output downloaded_site
"""

import argparse
import base64
import logging
import mimetypes
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
# Constants
# ---------------------------------------------------------------------------
DEFAULT_HOST = "192.168.100.1"
# Credentials can also be supplied via the ROUTER_USER / ROUTER_PASSWORD
# environment variables to avoid passing them on the command line.
DEFAULT_USER = os.environ.get("ROUTER_USER", "Mega_gpon")
DEFAULT_PASSWORD = os.environ.get("ROUTER_PASSWORD", "")
DEFAULT_OUTPUT = "downloaded_site"
LOGIN_PAGE = "/index.asp"
LOGIN_CGI = "/login.cgi"
RAND_COUNT_URL = "/asp/GetRandCount.asp"
REQUEST_TIMEOUT = 15          # seconds per HTTP request
DELAY_BETWEEN_REQUESTS = 0.3  # polite crawl delay (seconds)

# File extensions considered "static assets" that should always be downloaded
STATIC_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".svg", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".bmp", ".webp", ".json", ".xml", ".txt",
}

# Extensions / MIME types of pages to parse for further links
CRAWLABLE_TYPES = {
    "text/html", "application/xhtml+xml",
    "application/javascript", "text/javascript",
    "text/css",
}

# Patterns in a URL/path that suggest admin-panel pages worth crawling
ADMIN_PATH_HINTS = re.compile(
    r"\.(asp|html|htm|cgi|php|jsp)$", re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def build_session(host: str, verify_ssl: bool = True) -> requests.Session:
    """Return a Session pre-configured with retry logic and base URL."""
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
    return session


def base_url(host: str) -> str:
    return f"http://{host}"


def b64encode_password(password: str) -> str:
    """
    Replicates the router's base64encode(Password.value) call from util.js.
    The router uses standard Base64 (RFC 4648) on the UTF-8 bytes of the
    password string.
    """
    return base64.b64encode(password.encode("utf-8")).decode("ascii")


def get_rand_token(session: requests.Session, host: str) -> str:
    """
    POST to /asp/GetRandCount.asp – returns the anti-CSRF token that the
    login form requires as the 'x.X_HW_Token' field.
    """
    url = base_url(host) + RAND_COUNT_URL
    resp = session.post(url, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    token = resp.text.strip()
    log.debug("Received X_HW_Token: %s", token)
    return token


def login(session: requests.Session, host: str, username: str, password: str) -> bool:
    """
    Perform the two-step login used by the HG8145V5 admin interface:
      1. Fetch a one-time anti-CSRF token from /asp/GetRandCount.asp
      2. POST credentials (with base64-encoded password) to /login.cgi

    Returns True on success, False otherwise.
    """
    # Step 0 – load the login page so the router sets any initial cookies
    login_page_url = base_url(host) + LOGIN_PAGE
    try:
        session.get(login_page_url, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        log.warning("Could not load login page: %s", exc)

    # Step 1 – obtain anti-CSRF token
    try:
        token = get_rand_token(session, host)
    except requests.RequestException as exc:
        log.error("Failed to get auth token: %s", exc)
        return False

    # Step 2 – submit credentials
    payload = {
        "UserName": username,
        "PassWord": b64encode_password(password),
        "Language": "english",
        "x.X_HW_Token": token,
    }
    # The router's login.asp JavaScript sets a cookie whose value encodes the
    # selected UI language and an initial session id (-1 before auth completes).
    # Format expected by the router:  Cookie=body:Language:<lang>:id=-1;path=/
    # This replicates the line:
    #   var cookie2 = "Cookie=body:" + "Language:" + Language + ":" + "id=-1;path=/";
    #   document.cookie = cookie2;
    session.cookies.set(
        "Cookie",
        f"body:Language:english:id=-1;path=/",
        domain=host,
    )

    login_url = base_url(host) + LOGIN_CGI
    try:
        resp = session.post(
            login_url,
            data=payload,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        log.error("Login POST failed: %s", exc)
        return False

    # Heuristic: a successful login normally redirects to the main frame page.
    # If the response still contains the login form, the credentials were wrong.
    if "txt_Username" in resp.text or "txt_Password" in resp.text:
        log.error(
            "Login failed – the router returned the login form again. "
            "Check your credentials."
        )
        return False

    log.info("Login successful (HTTP %s)", resp.status_code)
    return True


# ---------------------------------------------------------------------------
# URL utilities
# ---------------------------------------------------------------------------

def normalise_url(url: str, page_url: str, base: str) -> str | None:
    """
    Convert any URL found in a page to an absolute URL on the same host.
    Returns None if the URL points to a different host or is unsupported.
    """
    url = url.strip()
    if not url or url.startswith(("data:", "javascript:", "mailto:", "#")):
        return None

    # Strip query string cache-busters (e.g. ?202406291158020553184798) but
    # keep the path – we need clean paths for file-system storage.
    parsed = urllib.parse.urlparse(url)

    # Make relative URLs absolute
    if not parsed.scheme:
        url = urllib.parse.urljoin(page_url, url)
        parsed = urllib.parse.urlparse(url)

    # Only follow links to the same router host
    if parsed.netloc and parsed.netloc != urllib.parse.urlparse(base).netloc:
        return None

    # Rebuild without query / fragment to get a canonical key
    canonical = urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, "", "", "")
    )
    return canonical


def url_to_local_path(url: str, base: str, output_dir: Path) -> Path:
    """
    Map an absolute URL to a local file system path inside *output_dir*,
    preserving the original directory structure of the web server.

    Examples:
        http://192.168.100.1/index.asp        → <output>/index.asp
        http://192.168.100.1/Cuscss/login.css → <output>/Cuscss/login.css
        http://192.168.100.1/                 → <output>/index.html
    """
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.lstrip("/")

    if not path:
        path = "index.html"
    elif path.endswith("/"):
        path = path + "index.html"

    local = output_dir / Path(path)
    return local


# ---------------------------------------------------------------------------
# Link extraction
# ---------------------------------------------------------------------------

def extract_links(content: str | bytes, content_type: str, page_url: str, base: str) -> set[str]:
    """
    Parse *content* and return a set of absolute URLs found in it.
    Handles HTML (all src/href/action attributes) and CSS (@import / url()).
    """
    found: set[str] = set()
    ct = content_type.split(";")[0].strip().lower()

    if isinstance(content, bytes):
        try:
            content = content.decode("utf-8", errors="replace")
        except Exception:
            return found

    if ct in ("text/html", "application/xhtml+xml"):
        soup = BeautifulSoup(content, "html.parser")

        # All standard resource attributes
        for tag, attr in [
            ("a", "href"), ("link", "href"), ("script", "src"),
            ("img", "src"), ("img", "data-src"),
            ("source", "src"), ("source", "srcset"),
            ("iframe", "src"), ("frame", "src"),
            ("form", "action"),
            ("input", "src"),
        ]:
            for el in soup.find_all(tag):
                val = el.get(attr)
                if val:
                    norm = normalise_url(val, page_url, base)
                    if norm:
                        found.add(norm)

        # Also parse inline <style> blocks for url() references
        for style_tag in soup.find_all("style"):
            found |= _extract_css_urls(style_tag.get_text(), page_url, base)

        # Scan raw JS/text for obvious .asp / .cgi references
        found |= _extract_path_literals(content, page_url, base)

    elif ct in ("text/css",):
        found |= _extract_css_urls(content, page_url, base)

    elif ct in ("application/javascript", "text/javascript"):
        found |= _extract_path_literals(content, page_url, base)

    return found


_CSS_URL_RE = re.compile(r"""url\(\s*['"]?([^)'"]+)['"]?\s*\)""", re.IGNORECASE)
_CSS_IMPORT_RE = re.compile(r"""@import\s+['"]([^'"]+)['"]""", re.IGNORECASE)


def _extract_css_urls(css: str, page_url: str, base: str) -> set[str]:
    found: set[str] = set()
    for pattern in (_CSS_URL_RE, _CSS_IMPORT_RE):
        for m in pattern.finditer(css):
            norm = normalise_url(m.group(1), page_url, base)
            if norm:
                found.add(norm)
    return found


# Match string literals that look like absolute or root-relative paths to
# known file types or admin CGI pages inside JS source.
_JS_PATH_RE = re.compile(
    r"""['"/]([a-zA-Z0-9_\-./]+\.(asp|html|htm|cgi|js|css|png|jpg|jpeg|gif|ico|svg|json|xml))""",
    re.IGNORECASE,
)


def _extract_path_literals(js: str, page_url: str, base: str) -> set[str]:
    found: set[str] = set()
    for m in _JS_PATH_RE.finditer(js):
        raw = m.group(0).lstrip("'\"/")
        # Only treat as absolute-path if it starts with '/'
        if m.group(0)[0] == "/":
            norm = normalise_url("/" + raw, page_url, base)
        else:
            norm = normalise_url(raw, page_url, base)
        if norm:
            found.add(norm)
    return found


# ---------------------------------------------------------------------------
# Downloader / Saver
# ---------------------------------------------------------------------------

def save_file(local_path: Path, content: bytes) -> None:
    """Write *content* to *local_path*, creating parent directories."""
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_bytes(content)


def download_url(
    session: requests.Session,
    url: str,
    base: str,
    output_dir: Path,
    visited: set[str],
    queue: deque,
) -> None:
    """
    Download a single URL, save it locally, and enqueue any new links found.
    """
    if url in visited:
        return
    visited.add(url)

    log.info("GET %s", url)
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    except requests.RequestException as exc:
        log.warning("Failed to fetch %s – %s", url, exc)
        return

    if resp.status_code == 401:
        log.warning("Session expired at %s – skipping", url)
        return
    if not resp.ok:
        log.warning("HTTP %s for %s – skipping", resp.status_code, url)
        return

    content_type = resp.headers.get("Content-Type", "application/octet-stream")
    content = resp.content

    # Save the file
    local_path = url_to_local_path(url, base, output_dir)
    save_file(local_path, content)
    log.debug("Saved → %s", local_path)

    # Parse for further links only on crawlable content types
    ct = content_type.split(";")[0].strip().lower()
    if ct in CRAWLABLE_TYPES:
        new_links = extract_links(content, content_type, url, base)
        for link in new_links:
            if link not in visited:
                queue.append(link)

    time.sleep(DELAY_BETWEEN_REQUESTS)


# ---------------------------------------------------------------------------
# Known admin pages seed list
# ---------------------------------------------------------------------------
# The router admin interface is mostly ASP / CGI based.  These are common
# page paths found on Huawei HG8145 devices – they are used as seeds in
# addition to whatever the crawler discovers automatically.
KNOWN_ADMIN_PAGES = [
    "/index.asp",
    "/login.asp",
    "/main.asp",
    "/main.html",
    "/frame.asp",
    "/asp/GetRandCount.asp",
    "/asp/GetRandInfo.asp",
    # Common resource directories (the crawler will follow links inside)
    "/Cuscss/login.css",
    "/Cuscss/english/frame.css",
    "/resource/common/md5.js",
    "/resource/common/util.js",
    "/resource/common/RndSecurityFormat.js",
    "/resource/common/safelogin.js",
    "/resource/common/jquery.min.js",
    "/frameaspdes/english/ssmpdes.js",
]


# ---------------------------------------------------------------------------
# Main crawler
# ---------------------------------------------------------------------------

def crawl(host: str, username: str, password: str, output_dir: str, verify_ssl: bool = True) -> None:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    log.info("Output directory: %s", out.resolve())
    log.info("Target router:    http://%s", host)
    log.info("Username:         %s", username)

    session = build_session(host, verify_ssl=verify_ssl)
    base = base_url(host)

    # --- Login ---
    if not login(session, host, username, password):
        sys.exit(1)

    # --- Seed queue ---
    visited: set[str] = set()
    queue: deque = deque()

    # Always start with the known pages
    for path in KNOWN_ADMIN_PAGES:
        queue.append(base + path)

    # Also seed with the login redirect target (usually /main.asp or similar)
    queue.append(base + "/")

    # --- Crawl loop ---
    while queue:
        url = queue.popleft()
        download_url(session, url, base, out, visited, queue)

    log.info("Crawl complete. %d URLs downloaded.", len(visited))
    log.info("Files saved in: %s", out.resolve())


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Huawei HG8145V5 router admin-panel crawler",
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
        help="Admin password",
    )
    parser.add_argument(
        "--output", default=DEFAULT_OUTPUT,
        help=f"Output directory (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--no-verify-ssl", dest="verify_ssl", action="store_false", default=True,
        help="Disable SSL certificate verification (opt-in for self-signed certs)",
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
        log.warning("SSL certificate verification is DISABLED (--no-verify-ssl)")

    if not args.password:
        import getpass
        args.password = getpass.getpass("Router password: ")

    crawl(
        host=args.host,
        username=args.user,
        password=args.password,
        output_dir=args.output,
        verify_ssl=args.verify_ssl,
    )


if __name__ == "__main__":
    main()
