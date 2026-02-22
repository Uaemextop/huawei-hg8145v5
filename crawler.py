#!/usr/bin/env python3
"""
Huawei HG8145V5 Router Web Crawler
====================================
Logs in to the router admin interface at 192.168.100.1, then crawls all
reachable pages and static assets, saving them to disk using the same
directory structure as the original web server so that the saved copy
can be browsed offline.

Compatible with Python 3.7+ on Windows and Linux.

Usage:
    python crawler.py [options]

Options:
    --host        Router IP/hostname  (default: 192.168.100.1)
    --user        Admin username      (default: Mega_gpon)
    --password    Admin password      (or set ROUTER_PASSWORD env var; prompted if omitted)
    --output      Output directory    (default: ./router_site)
    --timeout     Request timeout (s) (default: 15)
    --delay       Delay between requests in seconds (default: 0.3)
"""

import argparse
import base64
import getpass
import logging
import os
import re
import sys
import time
import urllib.parse
from pathlib import Path
from queue import Queue
from typing import List, Optional, Set

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print(
        "Missing required packages. Install them with:\n"
        "    pip install requests beautifulsoup4\n"
        "or:\n"
        "    pip install -r requirements.txt"
    )
    sys.exit(1)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("huawei_crawler")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_HOST = "192.168.100.1"
DEFAULT_USER = "Mega_gpon"
DEFAULT_OUTPUT = "router_site"
DEFAULT_TIMEOUT = 15
DEFAULT_DELAY = 0.3

# File extensions treated as static assets (saved; also scanned for embedded URLs)
STATIC_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp3", ".mp4",
    ".webm", ".json", ".xml", ".txt", ".pdf",
}

# Extensions/MIME types that contain HTML/links and should be crawled
CRAWLABLE_EXTENSIONS = {
    "", ".asp", ".html", ".htm", ".cgi", ".php", ".aspx",
}

# Extensions whose content should be scanned for embedded URL paths
_SCANNABLE_EXTENSIONS = {
    ".asp", ".html", ".htm", ".js", ".css", ".cgi", ".aspx", ".php", "",
}

# Compiled regex for numeric-only (cache-busting) query strings
_NUMERIC_QUERY_RE = re.compile(r"^\d+$")

# ---------------------------------------------------------------------------
# Compiled regexes for deep path extraction
# ---------------------------------------------------------------------------

# url() references in CSS
_CSS_URL_RE = re.compile(r"""url\s*\(\s*['"]?([^'"\)\s]+)['"]?\s*\)""", re.IGNORECASE)
# @import in CSS
_CSS_IMPORT_RE = re.compile(
    r"""@import\s+(?:url\s*\(\s*['"]?|['"])([^'"\)\s]+)""", re.IGNORECASE
)
# window.location = '...', location.href = '...'
_LOCATION_RE = re.compile(
    r"""(?:window\.)?location(?:\.href)?\s*=\s*['"]([^'"#\s]+)['"]"""
)
# url: '...' or url : '...' in JS objects / $.ajax
_URL_KEY_RE = re.compile(r"""[Uu]rl\s*:\s*['"]([^'"]+)['"]""")
# Form.setAction('...'), setAction("...")
_SET_ACTION_RE = re.compile(r"""[Ss]et[Aa]ction\s*\(\s*['"]([^'"]+)['"]""")
# src = '...', href = '...' in JS assignments (not preceded by a dot or word char)
_JS_ASSIGN_RE = re.compile(
    r"""(?:^|[^.\w])(?:src|href|action)\s*=\s*['"]([^'"#\s]+)['"]""", re.MULTILINE
)
# Generic: any quoted absolute path ending in a known extension.
# Pattern avoids catastrophic backtracking by using a flat structure.
_QUOTED_ABS_PATH_RE = re.compile(
    r"""['"](/[A-Za-z0-9_.\-/]+\.(?:asp|aspx|html?|cgi|js|css|png|jpg|jpeg|gif|ico|svg|json|xml|woff2?|ttf|eot|pdf|txt)(?:[?#][^'"<>\s]*)?)['"]"""
)

# Explicit set of content-types whose content should be scanned for links
_SCANNABLE_CONTENT_TYPES = frozenset({
    "text/html", "application/xhtml+xml",
    "application/javascript", "text/javascript",
    "text/css",
    "text/xml", "application/xml",
    "text/plain",
})

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def base64_encode(text: str) -> str:
    """Return the Base64 encoding of *text* (UTF-8) as an ASCII string."""
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def sanitize_filename(url_path: str) -> str:
    """
    Convert a URL path to a safe relative file-system path.

    Query strings are kept as part of the filename (special characters
    replaced) so that different parameterised URLs are saved separately.
    """
    # Remove leading slash
    url_path = url_path.lstrip("/")

    # Split path and query
    if "?" in url_path:
        path_part, query_part = url_path.split("?", 1)
        # Replace query string chars that are unsafe for filenames
        safe_query = re.sub(r'[\\/:*?"<>|]', "_", query_part)
        url_path = path_part + "__" + safe_query

    # Replace characters that are problematic on Windows
    url_path = re.sub(r'[*?"<>|]', "_", url_path)

    # Normalise path separators
    url_path = url_path.replace("/", os.sep)

    return url_path


def url_to_local_path(output_dir: Path, url: str, base_url: str) -> Path:
    """
    Given a full *url* return the local Path where it should be saved.

    Index-like URLs (ending with '/' or no extension) get an 'index.html'
    filename appended so they can be opened in a browser.
    """
    parsed = urllib.parse.urlparse(url)
    url_path = parsed.path + ("?" + parsed.query if parsed.query else "")

    rel = sanitize_filename(url_path)
    local = output_dir / rel

    # If the URL path ends with a separator or has no filename extension,
    # store it as a directory/index.html
    _, ext = os.path.splitext(parsed.path)
    if not ext or parsed.path.endswith("/"):
        local = local / "index.html" if not rel.endswith(os.sep + "index.html") else local

    return local


def guess_extension(content_type: str, url: str) -> str:
    """Return a suitable file extension for *content_type*."""
    ct = content_type.split(";")[0].strip().lower()
    mapping = {
        "text/html": ".html",
        "application/javascript": ".js",
        "text/javascript": ".js",
        "text/css": ".css",
        "image/png": ".png",
        "image/jpeg": ".jpg",
        "image/gif": ".gif",
        "image/x-icon": ".ico",
        "image/svg+xml": ".svg",
        "application/json": ".json",
        "text/plain": ".txt",
        "text/xml": ".xml",
        "application/xml": ".xml",
    }
    _, url_ext = os.path.splitext(urllib.parse.urlparse(url).path)
    if url_ext:
        return url_ext
    return mapping.get(ct, ".bin")


def _extract_paths_from_text(text: str, page_url: str, base_url: str) -> Set[str]:
    """
    Deeply scan any text (JS, ASP, CSS, HTML) for embedded URL path strings.

    Uses multiple regex patterns to cover:
    - CSS ``url()`` and ``@import``
    - JS ``window.location``, ``location.href`` assignments
    - JS AJAX ``url:`` properties
    - ``Form.setAction(...)`` calls
    - JS src/href/action assignments
    - Any quoted string with an absolute path ending in a known extension
    """
    links: Set[str] = set()
    parsed_base = urllib.parse.urlparse(base_url)

    def _add(href: Optional[str]) -> None:
        if not href:
            return
        href = href.strip()
        if href.startswith(("data:", "javascript:", "mailto:", "#")):
            return
        absolute = urllib.parse.urljoin(page_url, href)
        p = urllib.parse.urlparse(absolute)
        if p.netloc == parsed_base.netloc:
            clean = urllib.parse.urlunparse(p._replace(fragment=""))
            links.add(clean)

    for pattern in (
        _CSS_URL_RE,
        _CSS_IMPORT_RE,
        _LOCATION_RE,
        _URL_KEY_RE,
        _SET_ACTION_RE,
        _JS_ASSIGN_RE,
        _QUOTED_ABS_PATH_RE,
    ):
        for m in pattern.finditer(text):
            _add(m.group(1))

    return links


def extract_links(html: str, page_url: str, base_url: str) -> Set[str]:
    """
    Parse *html* and return all absolute URLs that belong to *base_url*.

    Combines:
    - BeautifulSoup tag-based extraction (href, src, action, …)
    - Deep text scan for paths embedded in JS, CSS, and ASP source
    """
    soup = BeautifulSoup(html, "html.parser")
    links: Set[str] = set()
    parsed_base = urllib.parse.urlparse(base_url)

    def add(href: Optional[str]) -> None:
        if not href:
            return
        if href.startswith(("data:", "javascript:", "mailto:", "#")):
            return
        absolute = urllib.parse.urljoin(page_url, href)
        parsed_abs = urllib.parse.urlparse(absolute)
        if parsed_abs.netloc == parsed_base.netloc:
            clean = urllib.parse.urlunparse(parsed_abs._replace(fragment=""))
            links.add(clean)

    # <a href>
    for tag in soup.find_all("a", href=True):
        add(tag["href"])

    # <link href>  (CSS, icons, etc.)
    for tag in soup.find_all("link", href=True):
        add(tag["href"])

    # <script src>
    for tag in soup.find_all("script", src=True):
        add(tag["src"])

    # <img src>
    for tag in soup.find_all("img", src=True):
        add(tag["src"])

    # <form action>
    for tag in soup.find_all("form", action=True):
        add(tag["action"])

    # <frame src> / <iframe src>
    for tag in soup.find_all(["frame", "iframe"], src=True):
        add(tag["src"])

    # Deep scan of the raw text (covers inline JS, CSS, ASP)
    links |= _extract_paths_from_text(html, page_url, base_url)

    return links


# ---------------------------------------------------------------------------
# Session / login
# ---------------------------------------------------------------------------

class RouterCrawler:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        output_dir: str,
        timeout: int,
        delay: float,
    ) -> None:
        self.base_url = f"http://{host}"
        self.username = username
        self.password = password
        self.output_dir = Path(output_dir)
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
        })
        # visited stores *canonical* URLs (cache-busters stripped) for dedup
        self.visited: Set[str] = set()
        self.queue: Queue = Queue()
        # Keep-alive: track when the session was last used and re-ping when idle.
        # Initialise to now so the first crawl iteration never triggers an
        # unnecessary ping (login() will refresh this timestamp anyway).
        self._last_activity: float = time.monotonic()
        self._keepalive_interval: float = 240.0  # seconds (4 min < typical 5 min idle timeout)

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------

    def _get_token(self) -> str:
        """
        Retrieve the anti-CSRF token from /asp/GetRandCount.asp.

        The router's login JS performs a POST to this endpoint, so we
        mirror that behaviour.  The response is a plain-text integer that
        must be submitted as the ``x.X_HW_Token`` field.
        """
        url = f"{self.base_url}/asp/GetRandCount.asp"
        try:
            resp = self.session.post(url, timeout=self.timeout)
            token = resp.text.strip()
            log.debug("Token: %s", token)
            return token
        except requests.RequestException as exc:
            log.warning("Could not fetch token: %s – using empty string", exc)
            return ""

    def login(self) -> bool:
        """
        Perform the two-step login:
          1. Set the language cookie.
          2. GET the token.
          3. POST credentials to /login.cgi.

        Returns True on success, False otherwise.
        """
        # Step 1 – set session cookie as the browser does
        self.session.cookies.set(
            "Cookie",
            f"body:Language:english:id=-1",
            domain=urllib.parse.urlparse(self.base_url).hostname,
            path="/",
        )

        # Step 2 – fetch login page to pick up any session cookies
        try:
            resp = self.session.get(
                f"{self.base_url}/index.asp",
                timeout=self.timeout,
            )
            log.info("Login page status: %s", resp.status_code)
        except requests.RequestException as exc:
            log.error("Cannot reach router at %s: %s", self.base_url, exc)
            return False

        # Step 3 – get CSRF token
        token = self._get_token()

        # Step 4 – submit credentials
        encoded_password = base64_encode(self.password)
        payload = {
            "UserName": self.username,
            "PassWord": encoded_password,
            "Language": "english",
            "x.X_HW_Token": token,
        }
        headers = {
            "Referer": f"{self.base_url}/index.asp",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        try:
            resp = self.session.post(
                f"{self.base_url}/login.cgi",
                data=payload,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True,
            )
            log.info("Login POST status: %s  URL: %s", resp.status_code, resp.url)
        except requests.RequestException as exc:
            log.error("Login POST failed: %s", exc)
            return False

        # Detect failure – routers typically redirect back to login.asp on fail
        if "login" in resp.url.lower() and resp.url.rstrip("/") != self.base_url.rstrip("/"):
            log.error("Login appears to have failed (redirected to %s)", resp.url)
            return False

        log.info("Login successful.")
        self._last_activity = time.monotonic()
        return True

    # ------------------------------------------------------------------
    # Crawling
    # ------------------------------------------------------------------

    def _save(self, url: str, content: bytes, content_type: str) -> Path:
        """Save *content* to disk, creating parent directories as needed."""
        parsed = urllib.parse.urlparse(url)
        rel_path = parsed.path.lstrip("/")

        # Determine local path
        if not rel_path or rel_path.endswith("/"):
            rel_path = rel_path.rstrip("/") + "/index.html"
        else:
            _, ext = os.path.splitext(rel_path)
            if not ext:
                # Add extension based on content-type
                rel_path += guess_extension(content_type, url)

        # Append query string as part of filename – but skip pure-numeric
        # cache-busting timestamps (e.g. ?202406291158020553184798)
        query = parsed.query
        if query and not _NUMERIC_QUERY_RE.match(query):
            base, ext = os.path.splitext(rel_path)
            safe_q = re.sub(r'[\\/:*?"<>|]', "_", query)
            rel_path = base + "__" + safe_q + ext

        # Windows-safe path
        parts = rel_path.replace("/", os.sep).split(os.sep)
        local = self.output_dir.joinpath(*parts)

        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_bytes(content)
        log.debug("Saved %s  →  %s", url, local)
        return local

    def _canon_url(self, url: str) -> str:
        """
        Return a canonical URL used for deduplication in the visited set.

        Strips pure-numeric cache-busting query strings (e.g. ?202406291158...).
        """
        parsed = urllib.parse.urlparse(url)
        query = parsed.query
        if _NUMERIC_QUERY_RE.match(query):
            query = ""
        return urllib.parse.urlunparse(parsed._replace(query=query, fragment=""))

    def _is_login_response(self, resp: requests.Response) -> bool:
        """Return True if *resp* is the login page (session may have expired)."""
        final_path = urllib.parse.urlparse(resp.url).path.lower()
        return final_path in ("/index.asp", "/login.asp", "/")

    def _local_path_for(self, url: str) -> Path:
        """
        Compute the local file path for *url* from the URL alone.

        Used to check whether a file was already saved in a previous run
        *before* making a network request.  The path follows the same
        scheme as :meth:`_save` but does not require the response
        content-type.
        """
        parsed = urllib.parse.urlparse(url)
        rel_path = parsed.path.lstrip("/")

        if not rel_path or rel_path.endswith("/"):
            rel_path = rel_path.rstrip("/") + "/index.html"

        query = parsed.query
        if query and not _NUMERIC_QUERY_RE.match(query):
            base, ext = os.path.splitext(rel_path)
            safe_q = re.sub(r'[\\/:*?"<>|]', "_", query)
            rel_path = base + "__" + safe_q + ext

        parts = rel_path.replace("/", os.sep).split(os.sep)
        return self.output_dir.joinpath(*parts)

    def _keepalive(self) -> None:
        """
        Proactively keep the authenticated session alive.

        Sends a lightweight GET to /asp/GetRandCount.asp when the session
        has been idle for *_keepalive_interval* seconds.  If the response
        looks like the login page (session expired), re-authenticates
        automatically.
        """
        if time.monotonic() - self._last_activity < self._keepalive_interval:
            return
        log.debug("Keepalive ping…")
        try:
            resp = self.session.get(
                f"{self.base_url}/asp/GetRandCount.asp",
                timeout=self.timeout,
            )
            self._last_activity = time.monotonic()
            if self._is_login_response(resp):
                log.info("Keepalive: session expired – re-authenticating…")
                self.login()
        except requests.RequestException as exc:
            log.warning("Keepalive ping failed: %s", exc)

    def _fetch(self, url: str) -> Optional[requests.Response]:
        """Fetch *url* with the authenticated session.

        If the router redirects to the login page (session expired), re-login
        once and retry the request.
        """
        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                stream=False,
            )
            self._last_activity = time.monotonic()
            # Detect session expiry (redirect back to login page for a non-login URL)
            if self._is_login_response(resp) and self._canon_url(url) not in (
                self._canon_url(f"{self.base_url}/index.asp"),
                self._canon_url(f"{self.base_url}/login.asp"),
                self._canon_url(f"{self.base_url}/"),
            ):
                log.info("Session expired while fetching %s – re-authenticating…", url)
                if self.login():
                    resp = self.session.get(
                        url,
                        timeout=self.timeout,
                        allow_redirects=True,
                        stream=False,
                    )
                    self._last_activity = time.monotonic()
            return resp
        except requests.RequestException as exc:
            log.warning("Failed to fetch %s: %s", url, exc)
            return None

    def _should_crawl_links(self, url: str, content_type: str) -> bool:
        """Return True if this response may contain links worth following."""
        ct = content_type.split(";")[0].strip().lower()
        if ct in _SCANNABLE_CONTENT_TYPES:
            return True
        _, ext = os.path.splitext(urllib.parse.urlparse(url).path)
        return ext.lower() in _SCANNABLE_EXTENSIONS

    def crawl(self) -> None:
        """
        BFS crawl starting from the router's root page.

        Saves every reachable resource that belongs to the router host.
        Continues recursively until no more new URLs are discovered.
        """
        # Seed with the root plus known Huawei admin paths so we reach every
        # section even if the main page doesn't link to it directly.
        seed_paths: List[str] = [
            "/",
            "/index.asp",
            "/login.asp",
            # ASP helpers
            "/asp/GetRandCount.asp",
            "/asp/GetRandInfo.asp",
            # Common admin page locations
            "/html/status.html",
            "/html/internet.html",
            "/html/lan.html",
            "/html/wlan.html",
            "/html/wlan5g.html",
            "/html/security.html",
            "/html/advanced.html",
            "/html/maintenance.html",
            "/html/voice.html",
            "/html/diagnosis.html",
            "/html/systemtools.html",
            "/html/firewall.html",
            "/html/nat.html",
            "/html/route.html",
            "/html/ddns.html",
            "/html/upnp.html",
            "/html/acl.html",
            "/html/qos.html",
            "/html/pon.html",
            "/html/deviceinfo.html",
            # Common resource roots
            "/resource/common/util.js",
            "/resource/common/md5.js",
            "/resource/common/jquery.min.js",
            "/resource/common/RndSecurityFormat.js",
            "/resource/common/safelogin.js",
            "/resource/common/crypto-js.js",
            "/frameaspdes/english/ssmpdes.js",
            "/Cuscss/login.css",
            "/Cuscss/english/frame.css",
        ]
        for path in seed_paths:
            self.queue.put(f"{self.base_url}{path}")

        while not self.queue.empty():
            url = self.queue.get()

            # Use canonical URL for deduplication
            canon = self._canon_url(url)

            if canon in self.visited:
                continue
            self.visited.add(canon)

            # Proactively keep the session alive before the next request
            self._keepalive()

            # ------------------------------------------------------------------
            # Skip if the file was already saved (resume across runs).
            # Even when skipping the download, scan the cached file for new
            # links so that a resumed crawl still discovers unvisited pages.
            # ------------------------------------------------------------------
            local_path = self._local_path_for(url)
            if local_path.exists():
                log.info("  ↷ already saved, skipping download → %s", local_path)
                if local_path.suffix.lower() in _SCANNABLE_EXTENSIONS:
                    try:
                        cached_text = local_path.read_text(encoding="utf-8", errors="replace")
                        new_links = extract_links(cached_text, url, self.base_url)
                        added = 0
                        for link in new_links:
                            if self._canon_url(link) not in self.visited:
                                self.queue.put(link)
                                added += 1
                        if added:
                            log.debug("  → queued %d new URL(s) from cached %s", added, local_path.name)
                    except OSError as exc:
                        log.warning("Could not read cached file %s: %s", local_path, exc)
                continue

            log.info("Fetching: %s", url)
            resp = self._fetch(url)
            if resp is None:
                continue

            if resp.status_code == 401:
                log.warning("401 Unauthorized for %s – skipping", url)
                continue

            if resp.status_code >= 400:
                log.warning("HTTP %s for %s – skipping", resp.status_code, url)
                continue

            content_type = resp.headers.get("Content-Type", "")
            content = resp.content

            # Save the file
            try:
                saved = self._save(url, content, content_type)
                log.info("  ✓ saved → %s", saved)
            except OSError as exc:
                log.warning("Could not save %s: %s", url, exc)

            # Extract and enqueue links from any scannable document
            if self._should_crawl_links(url, content_type):
                try:
                    text = content.decode("utf-8", errors="replace")
                except Exception:
                    text = ""
                new_links = extract_links(text, url, self.base_url)
                added = 0
                for link in new_links:
                    if self._canon_url(link) not in self.visited:
                        self.queue.put(link)
                        added += 1
                if added:
                    log.debug("  → queued %d new URL(s) from %s", added, url)

            time.sleep(self.delay)

        log.info("Crawl complete. %d URLs visited.", len(self.visited))

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self) -> int:
        """Login and crawl. Returns 0 on success, 1 on login failure."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        log.info("Output directory: %s", self.output_dir.resolve())
        log.info("Target: %s", self.base_url)

        if not self.login():
            log.error("Aborting due to login failure.")
            return 1

        self.crawl()
        return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Huawei HG8145V5 router web crawler – saves admin pages offline.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help="Router IP or hostname")
    parser.add_argument("--user", default=DEFAULT_USER, help="Admin username")
    parser.add_argument("--password", default=os.environ.get("ROUTER_PASSWORD", ""), help="Admin password (or set ROUTER_PASSWORD env var)")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output directory")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout (seconds)")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Delay between requests (seconds)")
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    password = args.password
    if not password:
        password = getpass.getpass(prompt="Router admin password: ")

    crawler = RouterCrawler(
        host=args.host,
        username=args.user,
        password=password,
        output_dir=args.output,
        timeout=args.timeout,
        delay=args.delay,
    )
    sys.exit(crawler.run())


if __name__ == "__main__":
    main()
