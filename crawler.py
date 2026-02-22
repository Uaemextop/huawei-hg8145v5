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
from typing import Optional, Set

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

# File extensions treated as static assets (always saved, never crawled for links)
STATIC_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp3", ".mp4",
    ".webm", ".json", ".xml", ".txt", ".pdf",
}

# Extensions/MIME types that contain HTML/links and should be crawled
CRAWLABLE_EXTENSIONS = {
    "", ".asp", ".html", ".htm", ".cgi", ".php", ".aspx",
}

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


def extract_links(html: str, page_url: str, base_url: str) -> Set[str]:
    """
    Parse *html* and return all absolute URLs that belong to *base_url*.
    """
    soup = BeautifulSoup(html, "html.parser")
    links: Set[str] = set()

    def add(href: Optional[str]) -> None:
        if not href:
            return
        # Skip data URIs, javascript: and mailto:
        if href.startswith(("data:", "javascript:", "mailto:", "#")):
            return
        absolute = urllib.parse.urljoin(page_url, href)
        # Only keep URLs on the same host
        parsed_abs = urllib.parse.urlparse(absolute)
        parsed_base = urllib.parse.urlparse(base_url)
        if parsed_abs.netloc == parsed_base.netloc:
            # Strip fragment
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

    # Inline JS: look for quoted paths starting with /
    for match in re.finditer(r"""['"](\/?[A-Za-z0-9_.~\-/%]+\.(?:asp|html?|cgi|js|css|png|jpg|gif|ico|svg)[^'"?]*(?:\?[^'"]*)?)['"]""", html):
        add(match.group(1))

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
        })
        self.visited: Set[str] = set()
        self.queue: Queue = Queue()

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------

    def _get_token(self) -> str:
        """
        Retrieve the anti-CSRF token from /asp/GetRandCount.asp.

        The router returns a plain-text integer that must be submitted
        as the ``x.X_HW_Token`` field.
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

        # Append query string as part of filename when present
        if parsed.query:
            base, ext = os.path.splitext(rel_path)
            safe_q = re.sub(r'[\\/:*?"<>|]', "_", parsed.query)
            rel_path = base + "__" + safe_q + ext

        # Windows-safe path
        parts = rel_path.replace("/", os.sep).split(os.sep)
        local = self.output_dir.joinpath(*parts)

        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_bytes(content)
        log.debug("Saved %s  →  %s", url, local)
        return local

    def _fetch(self, url: str) -> Optional[requests.Response]:
        """Fetch *url* with the authenticated session."""
        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                stream=False,
            )
            return resp
        except requests.RequestException as exc:
            log.warning("Failed to fetch %s: %s", url, exc)
            return None

    def _should_crawl_links(self, url: str, content_type: str) -> bool:
        """Return True if this response may contain links worth following."""
        ct = content_type.split(";")[0].strip().lower()
        if "html" in ct or "javascript" in ct or "xml" in ct:
            return True
        _, ext = os.path.splitext(urllib.parse.urlparse(url).path)
        return ext.lower() in CRAWLABLE_EXTENSIONS

    def crawl(self) -> None:
        """
        BFS crawl starting from the router's root page.

        Saves every reachable resource that belongs to the router host.
        """
        start_urls = [
            f"{self.base_url}/",
            f"{self.base_url}/index.asp",
        ]
        for u in start_urls:
            self.queue.put(u)

        while not self.queue.empty():
            url = self.queue.get()

            # Normalise URL (strip fragments)
            parsed = urllib.parse.urlparse(url)
            url = urllib.parse.urlunparse(parsed._replace(fragment=""))

            if url in self.visited:
                continue
            self.visited.add(url)

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

            # Extract and enqueue links if this is a crawlable document
            if self._should_crawl_links(url, content_type):
                try:
                    text = content.decode("utf-8", errors="replace")
                except Exception:
                    text = ""
                new_links = extract_links(text, url, self.base_url)
                for link in new_links:
                    if link not in self.visited:
                        self.queue.put(link)

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
