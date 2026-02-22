#!/usr/bin/env python3
"""
Huawei HG8145V5 Router Web Crawler

Crawls the Huawei HG8145V5 router web interface at 192.168.100.1,
authenticates using the login mechanism found in index.asp, and
downloads all accessible pages and resources preserving the original
directory structure for offline analysis.

The crawler is fully dynamic and recursive: it obtains cookies
automatically, parses **every** downloaded file (HTML, ASP, JS, CSS)
to discover new URLs, and keeps crawling until no new resources are
found.

Usage:
    python crawler.py [options]

Options:
    --host HOST        Router IP address (default: 192.168.100.1)
    --user USER        Login username (default: Mega_gpon)
    --password PASS    Login password (default: 796cce597901a5cf)
    --output DIR       Output directory (default: ./router_dump)
    --max-depth N      Maximum crawl depth, 0 for unlimited (default: 0)
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
DEFAULT_MAX_DEPTH = 0  # 0 = unlimited
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
    # Additional common .cgi endpoints
    "/asp/GetRandCount.asp",
    "/asp/GetRandInfo.asp",
]

# Extensions whose content should be scanned for further URLs.
# The crawler analyses ALL text content (JS, CSS, ASP, HTML, etc.)
# to discover every possible route.
PARSEABLE_EXTENSIONS = {
    ".asp", ".html", ".htm", ".cgi", ".js", ".css", "",
}

# Valid file extensions for paths found via regex heuristics.
VALID_PATH_EXTENSIONS = {
    ".asp", ".html", ".htm", ".cgi", ".js", ".css",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".map",
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
        self.max_depth = max_depth  # 0 means unlimited
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
        # Count consecutive failures to detect session expiry.
        self._consecutive_failures = 0
        self._max_consecutive_failures = 3
        # Keep-alive: re-verify session every N requests.
        self._request_count = 0
        self._keepalive_interval = 20
        self._max_relogin_attempts = 3

    # ------------------------------------------------------------------
    # Cookie helpers
    # ------------------------------------------------------------------
    def _log_cookies(self, label=""):
        """Log current session cookies for debugging."""
        cookies = {c.name: c.value for c in self.session.cookies}
        if cookies:
            logger.debug("Cookies%s: %s", f" ({label})" if label else "", cookies)
        return cookies

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------
    def login(self):
        """
        Authenticate with the router using the login flow from index.asp.

        Flow:
        1. GET /index.asp to initialise the session and capture cookies.
        2. POST /asp/GetRandCount.asp to obtain the CSRF token.
        3. POST /login.cgi with UserName, base64-encoded PassWord,
           Language, and the CSRF token.

        All cookies are captured and maintained automatically by
        requests.Session.
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
            self._log_cookies("after loading login page")
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

        # The router expects a cookie literally named "Cookie" with a
        # colon-delimited body containing the language and session id.
        # This matches the JS: document.cookie = "Cookie=body:Language:…"
        self.session.cookies.set(
            "Cookie", "body:Language:english:id=-1", path="/",
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
            self._log_cookies("after login")
        except requests.RequestException as exc:
            logger.error("Login request failed: %s", exc)
            return False

        # The router usually redirects to a main frame page on success.
        if resp.status_code == 200:
            logger.info("Login appears successful.")
            # Extract any links from the post-login page.
            if resp.text:
                self._extract_links(resp.text, resp.url or self.base_url, -1)
            self._consecutive_failures = 0
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

    def _try_relogin(self):
        """Attempt to re-authenticate when the session appears expired.

        Retries up to ``_max_relogin_attempts`` times with a short delay
        between attempts.
        """
        for attempt in range(1, self._max_relogin_attempts + 1):
            logger.warning(
                "Session may have expired – re-login attempt %d/%d …",
                attempt, self._max_relogin_attempts,
            )
            self._consecutive_failures = 0
            if self.login():
                logger.info("Re-login succeeded on attempt %d.", attempt)
                return True
            time.sleep(1)
        logger.error("Re-login failed after %d attempts.", self._max_relogin_attempts)
        return False

    def _check_session(self):
        """Proactive keep-alive: verify the session is still valid.

        Called periodically (every ``_keepalive_interval`` requests) to
        detect and recover from session expiry *before* it causes a
        string of failures.
        """
        try:
            resp = self.session.get(
                self.base_url + "/index.asp", timeout=10, verify=False,
            )
            if resp.status_code == 200 and not self._response_is_login_redirect(resp, "/index.asp"):
                logger.debug("Keep-alive check OK.")
                return True
        except requests.RequestException:
            pass
        logger.warning("Keep-alive check failed – session may have expired.")
        return self._try_relogin()

    def _response_is_login_redirect(self, resp, original_url):
        """Return True if the response indicates the session has expired.

        The router typically redirects to ``login.asp`` or serves the
        login page when the session is no longer valid.
        """
        # Check if we were redirected to the login page.
        if (
            'login.asp' in (resp.url or '')
            and 'login.asp' not in original_url
            and 'index.asp' not in original_url
        ):
            return True
        # Some firmware versions serve the login form directly.
        if resp.text and 'txt_Username' in resp.text and 'login.cgi' in resp.text:
            if 'login.asp' not in original_url and 'index.asp' not in original_url:
                return True
        return False

    # ------------------------------------------------------------------
    # Resumability – skip already-downloaded files
    # ------------------------------------------------------------------
    def _scan_existing_files(self):
        """Populate ``visited`` from files already on disk.

        This allows the crawler to resume a previous session without
        re-downloading files that were already saved.  Existing text
        files (ASP, HTML, JS, CSS) are also parsed for links so newly
        discovered URLs can still be crawled.
        """
        if not os.path.isdir(self.output_dir):
            return

        count = 0
        for dirpath, _dirnames, filenames in os.walk(self.output_dir):
            for fname in filenames:
                local_path = os.path.join(dirpath, fname)
                # Reconstruct the URL from the file path.
                rel = os.path.relpath(local_path, self.output_dir)
                # Normalise path separators to forward slashes.
                rel = rel.replace(os.sep, "/")
                url = self.base_url + "/" + rel
                normalised = self._normalise_url(url)
                self.visited.add(normalised)
                count += 1

                # Parse text files for links so we still discover new
                # URLs that may not have been crawled yet.
                ext = os.path.splitext(fname)[1].lower()
                if ext in PARSEABLE_EXTENSIONS:
                    try:
                        with open(local_path, "r", encoding="utf-8", errors="replace") as fh:
                            content = fh.read()
                        self._extract_links(content, url, 0)
                    except OSError:
                        pass

        if count:
            logger.info(
                "Resumed: found %d existing files in %s – they will be skipped.",
                count, self.output_dir,
            )

    # ------------------------------------------------------------------
    # Crawling
    # ------------------------------------------------------------------
    def crawl(self):
        """Run the main crawl loop.

        Crawls recursively and dynamically: every downloaded file is
        analysed for new URLs (HTML tags, JS string literals, CSS
        url() references, etc.) and the crawler keeps going until the
        queue is empty – i.e. no new resources are found.

        Files that already exist on disk from a previous run are
        skipped automatically (their content is still parsed for
        links so new pages can be discovered).
        """
        depth_desc = f"max depth {self.max_depth}" if self.max_depth else "unlimited depth"
        logger.info("Starting crawl (%s) …", depth_desc)

        # Resume support: load already-downloaded files into visited.
        self._scan_existing_files()

        # Seed the queue with known pages.
        for path in SEED_PATHS:
            url = self.base_url + path
            self.queue.append((url, 0))

        while self.queue:
            url, depth = self.queue.popleft()
            normalised = self._normalise_url(url)

            if normalised in self.visited:
                continue
            if self.max_depth and depth > self.max_depth:
                continue
            if not self._is_same_host(url):
                continue

            self.visited.add(normalised)

            # Periodic keep-alive check to catch session expiry early.
            self._request_count += 1
            if self._request_count % self._keepalive_interval == 0:
                self._check_session()

            content = self._download(url)
            if content is None:
                continue

            # Parse ALL text content for links – HTML, ASP, JS, CSS.
            path_str = urlparse(url).path
            ext = os.path.splitext(path_str)[1].lower()
            if ext in PARSEABLE_EXTENSIONS:
                self._extract_links(content, url, depth)

            if self.delay > 0:
                time.sleep(self.delay)

    def _download(self, url):
        """Download *url* and save it to the output directory.

        Returns the response body as text (or None on failure).
        Skips files that already exist on disk (resume support).
        Automatically re-authenticates if the session appears expired.
        """
        # --- Check if the file already exists on disk (resume) --------
        parsed = urlparse(url)
        rel_path = unquote(parsed.path).lstrip("/")
        if not rel_path or rel_path.endswith("/"):
            rel_path = rel_path + "index.html"
        local_path = os.path.join(self.output_dir, rel_path)

        if os.path.isfile(local_path):
            logger.debug("Already on disk, skipping download: %s", local_path)
            # Return existing content so links can still be extracted.
            ext = os.path.splitext(local_path)[1].lower()
            if ext in PARSEABLE_EXTENSIONS:
                try:
                    with open(local_path, "r", encoding="utf-8", errors="replace") as fh:
                        return fh.read()
                except OSError:
                    pass
            return None

        # --- Download -------------------------------------------------
        try:
            resp = self.session.get(url, timeout=15, verify=False)
        except requests.RequestException as exc:
            logger.warning("Failed to download %s: %s", url, exc)
            return None

        # Detect session expiry: the router often redirects to the
        # login page or returns a 302/401 when the session is lost.
        if resp.status_code in (302, 401, 403):
            self._consecutive_failures += 1
            if self._consecutive_failures >= self._max_consecutive_failures:
                logger.warning("Too many failures – attempting re-login.")
                if self._try_relogin():
                    try:
                        resp = self.session.get(url, timeout=15, verify=False)
                    except requests.RequestException:
                        return None
                else:
                    return None
            else:
                logger.debug("HTTP %s for %s", resp.status_code, url)
                return None

        if resp.status_code != 200:
            self._consecutive_failures += 1
            logger.debug("HTTP %s for %s", resp.status_code, url)
            return None

        # Detect login-page redirect in URL or response body.
        if self._response_is_login_redirect(resp, url):
            self._consecutive_failures += 1
            if self._consecutive_failures >= self._max_consecutive_failures:
                if self._try_relogin():
                    try:
                        resp = self.session.get(url, timeout=15, verify=False)
                    except requests.RequestException:
                        return None
                else:
                    return None
            else:
                return None

        self._consecutive_failures = 0
        self._log_cookies("after download")

        # local_path and rel_path were already computed above.
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
    def _extract_links(self, text, source_url, depth):
        """Parse *text* (HTML, JS, CSS, ASP) and enqueue discovered URLs.

        Analyses content exhaustively: HTML tags, inline JS, CSS url()
        references, string literals that look like router paths, and
        Huawei-specific JS patterns (setAction, $.ajax, RequestFile,
        loadLanguage, etc.).
        """
        if not text:
            return

        # --- HTML tag-based extraction (using BeautifulSoup) ----------
        soup = BeautifulSoup(text, "html.parser")

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

        # <form action>
        for tag in soup.find_all("form", action=True):
            self._enqueue(tag["action"], source_url, depth)

        # <input> with src (some routers use image inputs)
        for tag in soup.find_all("input", src=True):
            self._enqueue(tag["src"], source_url, depth)

        # <embed src>, <object data>
        for tag in soup.find_all("embed", src=True):
            self._enqueue(tag["src"], source_url, depth)
        for tag in soup.find_all("object", data=True):
            self._enqueue(tag["data"], source_url, depth)

        # --- Regex-based extraction (raw text) ------------------------
        self._extract_links_regex(text, source_url, depth)

    def _extract_links_regex(self, text, source_url, depth):
        """Extract URLs from raw text using regex patterns.

        Works on any text content: HTML, JS, CSS, ASP, etc.
        """
        # CSS url() references.
        for match in re.findall(r'url\(["\']?([^"\'()]+)["\']?\)', text):
            self._enqueue(match, source_url, depth)

        # src="…" / src='…' anywhere.
        for match in re.findall(r'src=["\']([^"\']+)["\']', text):
            self._enqueue(match, source_url, depth)

        # href="…" / href='…' anywhere.
        for match in re.findall(r'href=["\']([^"\']+)["\']', text):
            self._enqueue(match, source_url, depth)

        # window.location / .href = "…" redirects.
        for match in re.findall(
            r'(?:location|\.href)\s*=\s*["\']([^"\']+)["\']', text,
        ):
            self._enqueue(match, source_url, depth)

        # $.ajax url: '…' patterns.
        for match in re.findall(r"url\s*:\s*['\"]([^'\"]+)['\"]", text):
            self._enqueue(match, source_url, depth)

        # setAction('…') patterns (Huawei form submission).
        for match in re.findall(r"setAction\(['\"]([^'\"]+)['\"]\)", text):
            self._enqueue(match, source_url, depth)

        # loadLanguage("id", "/path/to/file.js", …)
        for match in re.findall(
            r'loadLanguage\([^,]+,\s*["\']([^"\']+)["\']', text,
        ):
            self._enqueue(match, source_url, depth)

        # RequestFile=/path/to/file.asp in query strings.
        for match in re.findall(r'RequestFile=([^\s&"\']+)', text):
            self._enqueue(match, source_url, depth)

        # Generic string literals that look like absolute router paths,
        # e.g. '/html/status/info.asp' or "/resource/common/util.js".
        # Matches a quoted string starting with / followed by path chars
        # and ending with a known file extension.
        _PATH_LITERAL_RE = (
            r"""(?:['"])(\/[a-zA-Z0-9_\-/.]+"""
            r"""\.(?:asp|js|css|html?|cgi|gif|jpg|png|ico))(?:['"])"""
        )
        for match in re.findall(_PATH_LITERAL_RE, text):
            self._enqueue(match, source_url, depth)

        # Bare .cgi endpoint references in string literals,
        # e.g. 'FrameModeSwitch.cgi' or "getCheckCode.cgi?&rand=…".
        _CGI_LITERAL_RE = r"""['\"]([a-zA-Z0-9_\-/]+\.cgi)(?:\?[^'"]*)?['"]"""
        for match in re.findall(_CGI_LITERAL_RE, text):
            self._enqueue(match, source_url, depth)

        # Bare .asp page references in string literals,
        # e.g. 'login.asp' or "/asp/GetRandCount.asp".
        _ASP_LITERAL_RE = r"""['\"]([a-zA-Z0-9_\-/]+\.asp)(?:\?[^'"]*)?['"]"""
        for match in re.findall(_ASP_LITERAL_RE, text):
            self._enqueue(match, source_url, depth)

        # document.write() patterns that inject tags with src or href,
        # e.g. document.write('<script src="/resource/common/crypto-js.js">').
        _DOC_WRITE_RE = r"""document\.write\(['"].*?(?:src|href)=['"]([^'"]+)"""
        for match in re.findall(_DOC_WRITE_RE, text):
            self._enqueue(match, source_url, depth)

        # Image source assignments: .src = '…'
        for match in re.findall(r'\.src\s*=\s*["\']([^"\']+)["\']', text):
            self._enqueue(match, source_url, depth)

    def _enqueue(self, raw_url, source_url, depth):
        """Resolve and enqueue a URL if it is worth fetching."""
        if not raw_url:
            return

        # Strip query strings and fragments for the file save,
        # but resolve relative paths first.
        raw_url = raw_url.split("?")[0].split("#")[0].strip()
        if not raw_url or raw_url.startswith("javascript:"):
            return
        if raw_url.startswith("data:"):
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
        cookies = {c.name: c.value for c in self.session.cookies}
        logger.info("  Session cookies: %s", cookies)
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
        help=f"Maximum crawl depth, 0 for unlimited (default: {DEFAULT_MAX_DEPTH})",
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
