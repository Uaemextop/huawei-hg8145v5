#!/usr/bin/env python3
"""
Huawei HG8145V5 Router Web Crawler

Crawls the Huawei HG8145V5 router web interface at 192.168.100.1,
authenticates using the login mechanism found in index.asp, and
downloads all accessible pages and resources preserving the original
directory structure for offline analysis.

Usage:
    python crawler.py [options]

Options:
    --host HOST        Router IP address (default: 192.168.100.1)
    --user USER        Login username (default: Mega_gpon)
    --password PASS    Login password (default: 796cce597901a5cf)
    --output DIR       Output directory (default: ./router_dump)
    --max-depth N      Maximum crawl depth (default: 10)
    --delay SECONDS    Delay between requests in seconds (default: 0.5)
"""

import argparse
import base64
import logging
import os
import re
import sys
import time
from collections import deque
from urllib.parse import urljoin, urlparse, unquote

import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------
DEFAULT_HOST = os.environ.get("HG8145V5_HOST", "192.168.100.1")
DEFAULT_USER = os.environ.get("HG8145V5_USER", "Mega_gpon")
DEFAULT_PASSWORD = os.environ.get("HG8145V5_PASSWORD", "796cce597901a5cf")
DEFAULT_OUTPUT = "router_dump"
DEFAULT_MAX_DEPTH = 10
DEFAULT_DELAY = 0.5

# Common admin pages known to exist on Huawei HG8145V5 routers.
# The crawler will also discover pages dynamically from links.
SEED_PATHS = [
    "/index.asp",
    "/login.asp",
    # Status pages
    "/html/status/deviceinformation/deviceinformation.asp",
    "/html/status/wanstatus/wanstatus.asp",
    "/html/status/opticinfo/opticinfo.asp",
    "/html/status/UserDevInfo/UserDevInfo.asp",
    "/html/status/ethinfo/ethinfo.asp",
    "/html/status/wlanbasic/wlanbasic.asp",
    "/html/status/voipstatus/voipstatus.asp",
    # WAN config
    "/html/network/wan/wan.asp",
    "/html/network/wan6/wan6.asp",
    # WLAN config
    "/html/network/wlanbasic/wlanbasic.asp",
    "/html/network/wlanadvance/wlanadvance.asp",
    "/html/network/wlansecurity/wlansecurity.asp",
    "/html/network/wlanacl/wlanacl.asp",
    "/html/network/wps/wps.asp",
    # LAN config
    "/html/network/landhcp/landhcpserver.asp",
    "/html/network/lanipv6/lanipv6.asp",
    # Security
    "/html/advance/firewall/firewall.asp",
    "/html/advance/aclservice/aclservice.asp",
    "/html/advance/ddos/ddos.asp",
    # Advance
    "/html/advance/route/route.asp",
    "/html/advance/route6/route6.asp",
    "/html/advance/nat/nat.asp",
    "/html/advance/natdmz/natdmz.asp",
    "/html/advance/dns/dns.asp",
    "/html/advance/upnp/upnp.asp",
    # System / Management
    "/html/advance/ntp/ntp.asp",
    "/html/advance/device/device.asp",
    "/html/advance/management/management.asp",
    "/html/advance/log/log.asp",
    "/html/amp/accountmgnt/accountmgnt.asp",
    "/html/amp/reboot/reboot.asp",
    "/html/amp/restore/restore.asp",
    "/html/amp/upgrade/upgrade.asp",
    "/html/amp/cfgfile/cfgfile.asp",
    # VOIP
    "/html/network/voip/voip.asp",
    # Resources referenced in index.asp
    "/Cuscss/login.css",
    "/Cuscss/english/frame.css",
    "/resource/common/md5.js",
    "/resource/common/util.js",
    "/resource/common/RndSecurityFormat.js",
    "/resource/common/safelogin.js",
    "/resource/common/jquery.min.js",
    "/resource/common/crypto-js.js",
    "/frameaspdes/english/ssmpdes.js",
]

# File extensions considered as downloadable resources.
RESOURCE_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp",
    ".svg", ".woff", ".woff2", ".ttf", ".eot", ".map",
}

# Extensions that may contain links to crawl further.
CRAWLABLE_EXTENSIONS = {
    ".asp", ".html", ".htm", ".cgi", "",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Crawler class
# ---------------------------------------------------------------------------
class HuaweiCrawler:
    """Crawl and download the Huawei HG8145V5 router web interface."""

    def __init__(self, host, username, password, output_dir, max_depth, delay):
        self.base_url = f"http://{host}"
        self.host = host
        self.username = username
        self.password = password
        self.output_dir = output_dir
        self.max_depth = max_depth
        self.delay = delay

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Referer": self.base_url + "/index.asp",
        })

        # Track visited URLs to avoid re-downloading.
        self.visited = set()
        # Track saved file paths.
        self.saved_files = []
        # Queue of (url, depth) tuples.
        self.queue = deque()

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------
    def login(self):
        """
        Authenticate with the router using the login flow from index.asp.

        Flow:
        1. GET /index.asp to initialise the session.
        2. POST /asp/GetRandCount.asp to obtain the CSRF token.
        3. POST /login.cgi with UserName, base64-encoded PassWord,
           Language, and the CSRF token.
        """
        logger.info("Starting login to %s as '%s' …", self.base_url, self.username)

        # Step 1 – load the login page to get initial cookies.
        try:
            # verify=False is required because router admin interfaces
            # typically use self-signed TLS certificates.
            resp = self.session.get(
                self.base_url + "/index.asp", timeout=15, verify=False,
            )
            resp.raise_for_status()
            logger.info("Loaded login page (HTTP %s).", resp.status_code)
        except requests.RequestException as exc:
            logger.error("Cannot reach router at %s: %s", self.base_url, exc)
            return False

        # Step 2 – obtain CSRF token from GetRandCount.asp.
        token = self._get_csrf_token()
        if token is None:
            logger.error("Failed to obtain CSRF token.")
            return False
        logger.info("Obtained CSRF token.")

        # Step 3 – submit login form.
        password_b64 = base64.b64encode(self.password.encode("utf-8")).decode("ascii")

        # Set the cookie expected by the router.
        self.session.cookies.set(
            "Cookie", f"body:Language:english:id=-1", path="/",
        )

        login_data = {
            "UserName": self.username,
            "PassWord": password_b64,
            "Language": "english",
            "x.X_HW_Token": token,
        }

        try:
            resp = self.session.post(
                self.base_url + "/login.cgi",
                data=login_data,
                timeout=15,
                verify=False,
                allow_redirects=True,
            )
            logger.info("Login response: HTTP %s, URL: %s", resp.status_code, resp.url)
        except requests.RequestException as exc:
            logger.error("Login request failed: %s", exc)
            return False

        # The router usually redirects to a main frame page on success.
        if resp.status_code == 200:
            logger.info("Login appears successful.")
            return True

        logger.warning(
            "Login may have failed (HTTP %s). Continuing anyway …", resp.status_code,
        )
        return True  # Continue crawling even if uncertain.

    def _get_csrf_token(self):
        """Fetch the anti-CSRF token from /asp/GetRandCount.asp."""
        try:
            resp = self.session.post(
                self.base_url + "/asp/GetRandCount.asp",
                timeout=10,
                verify=False,
            )
            resp.raise_for_status()
            token = resp.text.strip()
            if token:
                return token
        except requests.RequestException as exc:
            logger.warning("GetRandCount.asp request failed: %s", exc)
        return None

    # ------------------------------------------------------------------
    # Crawling
    # ------------------------------------------------------------------
    def crawl(self):
        """Run the main crawl loop."""
        logger.info("Starting crawl with max depth %d …", self.max_depth)

        # Seed the queue with known pages.
        for path in SEED_PATHS:
            url = self.base_url + path
            self.queue.append((url, 0))

        while self.queue:
            url, depth = self.queue.popleft()
            normalised = self._normalise_url(url)

            if normalised in self.visited:
                continue
            if depth > self.max_depth:
                continue
            if not self._is_same_host(url):
                continue

            self.visited.add(normalised)

            content = self._download(url)
            if content is None:
                continue

            # Determine if we should parse for more links.
            path = urlparse(url).path
            ext = os.path.splitext(path)[1].lower()
            if ext in CRAWLABLE_EXTENSIONS:
                self._extract_links(content, url, depth)

            if self.delay > 0:
                time.sleep(self.delay)

    def _download(self, url):
        """Download *url* and save it to the output directory.

        Returns the response body as text (or None on failure).
        """
        try:
            resp = self.session.get(url, timeout=15, verify=False)
        except requests.RequestException as exc:
            logger.warning("Failed to download %s: %s", url, exc)
            return None

        if resp.status_code != 200:
            logger.debug("HTTP %s for %s", resp.status_code, url)
            return None

        # Determine local file path from the URL path.
        parsed = urlparse(url)
        rel_path = unquote(parsed.path).lstrip("/")
        if not rel_path or rel_path.endswith("/"):
            rel_path = rel_path + "index.html"

        # Remove query string artefacts from the saved file name.
        local_path = os.path.join(self.output_dir, rel_path)
        local_dir = os.path.dirname(local_path)

        os.makedirs(local_dir, exist_ok=True)

        # Decide binary vs text.
        content_type = resp.headers.get("Content-Type", "")
        is_binary = self._is_binary_content(content_type, rel_path)

        try:
            if is_binary:
                with open(local_path, "wb") as fh:
                    fh.write(resp.content)
            else:
                with open(local_path, "w", encoding="utf-8", errors="replace") as fh:
                    fh.write(resp.text)
        except OSError as exc:
            logger.warning("Cannot write %s: %s", local_path, exc)
            return None

        self.saved_files.append(local_path)
        logger.info("Saved %s → %s", url, local_path)

        return resp.text if not is_binary else None

    # ------------------------------------------------------------------
    # Link extraction
    # ------------------------------------------------------------------
    def _extract_links(self, html, source_url, depth):
        """Parse *html* and enqueue any discovered links."""
        if not html:
            return

        soup = BeautifulSoup(html, "html.parser")

        # <a href>, <area href>
        for tag in soup.find_all(["a", "area"], href=True):
            self._enqueue(tag["href"], source_url, depth)

        # <script src>
        for tag in soup.find_all("script", src=True):
            self._enqueue(tag["src"], source_url, depth)

        # <link href> (CSS, icons)
        for tag in soup.find_all("link", href=True):
            self._enqueue(tag["href"], source_url, depth)

        # <img src>
        for tag in soup.find_all("img", src=True):
            self._enqueue(tag["src"], source_url, depth)

        # <frame src>, <iframe src>
        for tag in soup.find_all(["frame", "iframe"], src=True):
            self._enqueue(tag["src"], source_url, depth)

        # Inline url() references in style attributes and <style> blocks.
        for match in re.findall(r'url\(["\']?([^"\'()]+)["\']?\)', html):
            self._enqueue(match, source_url, depth)

        # document.write('<script … src="…">') patterns.
        for match in re.findall(r'src=["\']([^"\']+)["\']', html):
            self._enqueue(match, source_url, depth)

        # href="…" anywhere (catches dynamically-written links).
        for match in re.findall(r'href=["\']([^"\']+)["\']', html):
            self._enqueue(match, source_url, depth)

        # window.location or .href = "…" redirects.
        for match in re.findall(r'(?:location|href)\s*=\s*["\']([^"\']+)["\']', html):
            self._enqueue(match, source_url, depth)

        # $.ajax url: '…' patterns.
        for match in re.findall(r"url\s*:\s*['\"]([^'\"]+)['\"]", html):
            self._enqueue(match, source_url, depth)

        # setAction('…') patterns (form actions in the router JS).
        for match in re.findall(r"setAction\(['\"]([^'\"]+)['\"]\)", html):
            self._enqueue(match, source_url, depth)

        # loadLanguage references.
        for match in re.findall(
            r'loadLanguage\([^,]+,\s*["\']([^"\']+)["\']', html,
        ):
            self._enqueue(match, source_url, depth)

    def _enqueue(self, raw_url, source_url, depth):
        """Resolve and enqueue a URL if it is worth fetching."""
        # Strip query strings and fragments for the file save,
        # but resolve relative paths first.
        raw_url = raw_url.split("?")[0].split("#")[0].strip()
        if not raw_url or raw_url.startswith("javascript:"):
            return

        absolute = urljoin(source_url, raw_url)
        normalised = self._normalise_url(absolute)

        if normalised in self.visited:
            return
        if not self._is_same_host(absolute):
            return

        self.queue.append((absolute, depth + 1))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _normalise_url(url):
        """Return a canonical version of *url* for deduplication."""
        parsed = urlparse(url)
        path = parsed.path.rstrip("/") or "/"
        return f"{parsed.scheme}://{parsed.hostname}{path}"

    def _is_same_host(self, url):
        """Return True if *url* belongs to the router."""
        parsed = urlparse(url)
        return parsed.hostname == self.host

    @staticmethod
    def _is_binary_content(content_type, path):
        """Guess whether content should be saved as binary."""
        binary_types = ("image/", "font/", "application/octet", "application/zip")
        if any(bt in content_type for bt in binary_types):
            return True
        ext = os.path.splitext(path)[1].lower()
        return ext in {
            ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".svg",
            ".woff", ".woff2", ".ttf", ".eot", ".zip", ".tar", ".gz",
        }

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    def print_summary(self):
        """Print a short summary of what was downloaded."""
        logger.info("=" * 60)
        logger.info("Crawl complete.")
        logger.info("  URLs visited  : %d", len(self.visited))
        logger.info("  Files saved   : %d", len(self.saved_files))
        logger.info("  Output folder : %s", os.path.abspath(self.output_dir))
        logger.info("=" * 60)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Huawei HG8145V5 Router Web Crawler",
    )
    parser.add_argument(
        "--host", default=DEFAULT_HOST,
        help=f"Router IP address (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--user", default=DEFAULT_USER,
        help=f"Login username (default: {DEFAULT_USER})",
    )
    parser.add_argument(
        "--password", default=DEFAULT_PASSWORD,
        help="Login password",
    )
    parser.add_argument(
        "--output", default=DEFAULT_OUTPUT,
        help=f"Output directory (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--max-depth", type=int, default=DEFAULT_MAX_DEPTH,
        help=f"Maximum crawl depth (default: {DEFAULT_MAX_DEPTH})",
    )
    parser.add_argument(
        "--delay", type=float, default=DEFAULT_DELAY,
        help=f"Delay between requests in seconds (default: {DEFAULT_DELAY})",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    crawler = HuaweiCrawler(
        host=args.host,
        username=args.user,
        password=args.password,
        output_dir=args.output,
        max_depth=args.max_depth,
        delay=args.delay,
    )

    if not crawler.login():
        logger.error("Login failed. Exiting.")
        sys.exit(1)

    crawler.crawl()
    crawler.print_summary()


if __name__ == "__main__":
    main()
