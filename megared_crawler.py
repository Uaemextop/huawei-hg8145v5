#!/usr/bin/env python3
"""
Megared.net.mx Web Crawler & Index File Finder
================================================
Crawls the MEGACABLE ISP public web infrastructure at megared.net.mx and its
known subdomains, searching for index files (index.html, index.php, index.asp,
default.aspx, etc.) and reporting their locations.

MEGACABLE (megared.net.mx) is the ISP that manages Huawei HG8145V5 ONT devices
via TR-069/CWMP.  This crawler maps publicly reachable endpoints and catalogues
every index/default document found.

Usage
-----
    pip install -r requirements.txt

    # Basic crawl (default depth=2, max 200 pages)
    python megared_crawler.py

    # Deeper crawl
    python megared_crawler.py --depth 3 --max-pages 500

    # Custom output directory
    python megared_crawler.py --output megared_output

    # Include non-standard ports (e.g. TR-069 port 7547)
    python megared_crawler.py --include-ports

    # Verbose debug logging
    python megared_crawler.py --debug
"""

import argparse
import hashlib
import json
import logging
import os
import platform
import re
import socket
import subprocess
import sys
import time
import urllib.parse
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
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

try:
    import lxml  # noqa: F401
    _BS4_PARSER = "lxml"
except ImportError:
    _BS4_PARSER = "html.parser"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log = logging.getLogger("megared-crawler")


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
# Configuration
# ---------------------------------------------------------------------------
BASE_DOMAIN = "megared.net.mx"
DEFAULT_OUTPUT = "megared_output"
DEFAULT_DEPTH = 2
DEFAULT_MAX_PAGES = 200
DEFAULT_DELAY = 0.5   # polite delay between requests (seconds)
DEFAULT_TIMEOUT = 10  # seconds per HTTP request
REQUEST_TIMEOUT = DEFAULT_TIMEOUT  # module-level alias (set by CLI --timeout)
REACHABILITY_TCP_TIMEOUT = 3      # shorter timeout for TCP reachability probes
REACHABILITY_HTTP_TIMEOUT = 5     # shorter timeout for HTTP HEAD reachability probes
CONNECTION_RESET_MAX_RETRIES = 3

# Known subdomains and endpoints for megared.net.mx (MEGACABLE ISP)
KNOWN_SUBDOMAINS = [
    "megared.net.mx",
    "www.megared.net.mx",
    "acsvip.megared.net.mx",
    "mail.megared.net.mx",
    "webmail.megared.net.mx",
    "portal.megared.net.mx",
    "soporte.megared.net.mx",
    "admin.megared.net.mx",
    "ftp.megared.net.mx",
    "dns.megared.net.mx",
    "ns1.megared.net.mx",
    "ns2.megared.net.mx",
    "api.megared.net.mx",
    "servicios.megared.net.mx",
    "clientes.megared.net.mx",
]

# Additional ports to probe when --include-ports is set
EXTRA_PORTS = [80, 443, 8080, 8443, 7547]

# Index file names to search for
INDEX_FILENAMES = [
    "index.html",
    "index.htm",
    "index.php",
    "index.asp",
    "index.aspx",
    "index.jsp",
    "index.jhtml",
    "index.cgi",
    "index.shtml",
    "index.xhtml",
    "index.mhtml",
    "index.phtml",
    "index.rhtml",
    "index.jspx",
    "index.jsf",
    "index.faces",
    "index.wss",
    "index.pl",
    "index.py",
    "index.rb",
    "index.cfm",
    "index.do",
    "index.action",
    "index.xml",
    "index.json",
    "index.txt",
    "index.nsf",
    "index.yaws",
    "default.html",
    "default.htm",
    "default.asp",
    "default.aspx",
    "Default.aspx",
    "home.html",
    "home.php",
    "home.asp",
    "home.jsp",
    "welcome.html",
    "main.html",
    "main.asp",
    "main.php",
    "main.jsp",
]

# Content types that we parse for links
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

# Common paths to probe for index files
COMMON_PATHS = [
    "/",
    "/admin/",
    "/login/",
    "/portal/",
    "/webmail/",
    "/mail/",
    "/panel/",
    "/cpanel/",
    "/control/",
    "/api/",
    "/service/",
    "/service/cwmp",
    "/services/",
    "/cgi-bin/",
    "/app/",
    "/web/",
    "/docs/",
    "/help/",
    "/soporte/",
    "/clientes/",
    "/firmware/",
    "/firmware/update/",
    "/firmware/download/",
    "/fw/",
    "/update/",
    "/upgrade/",
    "/download/",
    "/files/",
    "/images/",
    "/acs/",
]

# Pool of User-Agent strings rotated when connection resets occur.
# Servers sometimes reset connections based on UA fingerprinting; rotating
# the UA on each retry increases the chance of a successful reconnection.
#
# Firmware-extracted UAs (from EG8145V5 V500R022C00SPC340B019 rootfs):
#   • "HuaweiHomeGateway"      – main CWMP session UA (libhw_smp_cwmp_core.so)
#   • "HW-FTTH"                – bulk data upload UA   (libhw_cwmp_bulkchina.so)
#   • "HW_IPMAC_REPORT"        – MAC report UA         (libhw_cwmp_china_pdt.so)
#   • MSIE 9.0 / 2345Explorer  – web market UA         (libhw_smp_base.so)
#   • MSIE 8.0 / WOW64         – HTTP client UA        (libhw_smp_httpclient.so)
_ALTERNATE_USER_AGENTS = [
    # --- Firmware-extracted UAs (highest priority) ---
    # Main CWMP session UA (found in libhw_smp_cwmp_core.so at 0xb5fa9)
    "HuaweiHomeGateway",
    # Bulk data upload UA (libhw_cwmp_bulkchina.so)
    "HW-FTTH",
    # IP/MAC report UA (libhw_cwmp_china_pdt.so)
    "HW_IPMAC_REPORT",
    # Web market client UA (libhw_smp_base.so)
    (
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; "
        "Trident/5.0; 2345Explorer)"
    ),
    # HTTP client UA (libhw_smp_httpclient.so)
    (
        "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; "
        "Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; "
        ".NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0E; .NET4.0C)"
    ),
    # --- Standard browser UAs ---
    # Chrome on Windows
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    # Firefox on Linux
    (
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) "
        "Gecko/20100101 Firefox/121.0"
    ),
    # curl-style (minimal)
    "curl/8.4.0",
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class IndexFileResult:
    """Represents a discovered index file."""
    url: str
    status_code: int
    content_type: str
    content_length: int
    server: str
    title: str
    redirect_url: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class CrawlReport:
    """Aggregated results of a megared.net.mx crawl."""
    start_time: str = ""
    end_time: str = ""
    target_domain: str = BASE_DOMAIN
    subdomains_probed: list = field(default_factory=list)
    urls_visited: int = 0
    index_files_found: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    all_discovered_urls: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "start_time": self.start_time,
            "end_time": self.end_time,
            "target_domain": self.target_domain,
            "subdomains_probed": self.subdomains_probed,
            "urls_visited": self.urls_visited,
            "index_files_found": [
                {
                    "url": r.url,
                    "status_code": r.status_code,
                    "content_type": r.content_type,
                    "content_length": r.content_length,
                    "server": r.server,
                    "title": r.title,
                    "redirect_url": r.redirect_url,
                    "timestamp": r.timestamp,
                }
                for r in self.index_files_found
            ],
            "errors": self.errors,
            "total_index_files": len(self.index_files_found),
            "total_urls_discovered": len(self.all_discovered_urls),
        }

    def save(self, output_dir: Path) -> Path:
        report_path = output_dir / "crawl_report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return report_path


# ---------------------------------------------------------------------------
# HTTP session
# ---------------------------------------------------------------------------

def build_session(verify_ssl: bool = False) -> requests.Session:
    """Return a requests.Session with retry logic and browser-like headers."""
    session = requests.Session()
    retry = Retry(
        total=2,
        backoff_factor=0.5,
        status_forcelist=[502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = verify_ssl
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": "es-MX,es;q=0.9,en;q=0.8",
        "Connection": "keep-alive",
    })
    return session


# ---------------------------------------------------------------------------
# Host reachability – fallback when ICMP ping is blocked
# ---------------------------------------------------------------------------

def dns_resolves(host: str) -> bool:
    """
    Return True if *host* resolves to at least one IP address via DNS.

    This is the cheapest possible reachability pre-check.  Hosts that do not
    resolve are guaranteed unreachable — skipping them avoids spending 40+
    seconds on TCP/HTTP timeout chains per dead subdomain.
    """
    try:
        socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return True
    except (socket.gaierror, OSError):
        return False


def ping_host(host: str, timeout: int = 2) -> bool:
    """
    Send an ICMP ping to *host*.  Returns True if the host replies.

    Many servers (including megared.net.mx) block ICMP, so a False result
    does NOT mean the host is unreachable – use :func:`check_host_reachable`
    which falls back to TCP/HTTP probes.
    """
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        result = subprocess.run(
            ["ping", param, "1", "-W", str(timeout), host],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def tcp_connect(host: str, port: int = 443, timeout: int = REACHABILITY_TCP_TIMEOUT) -> bool:
    """Try a raw TCP connection to *host*:*port*.  Returns True on success."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, socket.error, OSError):
        return False


def http_head_check(
    host: str,
    session: requests.Session | None = None,
    timeout: int = REACHABILITY_HTTP_TIMEOUT,
) -> dict:
    """
    Perform an HTTP(S) HEAD request to determine reachability and basic
    server information.  Returns a dict with ``reachable``, ``status``,
    ``server``, ``url``, and ``method`` keys.

    Tries HTTPS first, then falls back to HTTP.
    """
    s = session or build_session()
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            resp = s.head(url, timeout=timeout, allow_redirects=True)
            return {
                "reachable": True,
                "status": resp.status_code,
                "server": resp.headers.get("Server", ""),
                "url": resp.url,
                "method": "HEAD",
                "scheme": scheme,
            }
        except requests.RequestException:
            continue
    return {"reachable": False, "status": 0, "server": "", "url": "",
            "method": "HEAD", "scheme": ""}


def check_host_reachable(
    host: str,
    session: requests.Session | None = None,
) -> dict:
    """
    Multi-strategy reachability check for a hostname.

    0. DNS resolution – instant reject if hostname does not resolve.
    1. ICMP ping – fastest but often blocked by firewalls.
    2. TCP connect to port 443 (HTTPS) – works even if ICMP is blocked.
    3. TCP connect to port 80 (HTTP) – fallback for plain-HTTP servers
       (skipped if port 443 already succeeded).
    4. HTTP HEAD request – confirms the web server is responding.

    Returns a dict describing which method succeeded and server details.
    This is the recommended way to check if a megared.net.mx subdomain
    is alive before crawling it.
    """
    result = {
        "host": host,
        "dns": False,
        "ping": False,
        "tcp_443": False,
        "tcp_80": False,
        "http": {"reachable": False},
        "reachable": False,
        "method": "",
    }

    # Step 0 – DNS resolution (instant; avoids 40s+ of timeouts)
    if not dns_resolves(host):
        log.debug("Host %s does not resolve in DNS – skipping.", host)
        return result
    result["dns"] = True

    # Step 1 – ICMP ping (quick, often blocked)
    result["ping"] = ping_host(host)
    if result["ping"]:
        result["reachable"] = True
        result["method"] = "ping"
        log.debug("Host %s responds to ping.", host)
    else:
        log.debug("Host %s does not respond to ping (ICMP may be blocked).", host)

    # Step 2 – TCP probes (works when ping is blocked)
    result["tcp_443"] = tcp_connect(host, 443)
    if result["tcp_443"]:
        result["reachable"] = True
        if not result["method"]:
            result["method"] = "tcp:443"
        log.debug("Host %s has port 443 open.", host)

    # Only check port 80 if 443 failed (avoids redundant 3s timeout)
    if not result["reachable"]:
        result["tcp_80"] = tcp_connect(host, 80)
        if result["tcp_80"]:
            result["reachable"] = True
            result["method"] = "tcp:80"
            log.debug("Host %s has port 80 open.", host)

    # Step 3 – HTTP HEAD (confirms web server is answering)
    # Skip HTTP HEAD entirely if both TCP probes failed — the HEAD
    # request would just timeout too, wasting 10+ seconds.
    if result["reachable"]:
        http_info = http_head_check(host, session)
        result["http"] = http_info
        if http_info["reachable"]:
            if not result["method"]:
                result["method"] = "http"
            log.debug("Host %s HTTP reachable: %s (status %d, server=%s)",
                      host, http_info["url"], http_info["status"],
                      http_info["server"])

    if not result["reachable"]:
        log.info("Host %s is unreachable (ping blocked, no open ports).", host)

    return result


# ---------------------------------------------------------------------------
# HTTP rejection handling
# ---------------------------------------------------------------------------

# Retry-After header parser
_RETRY_AFTER_RE = re.compile(r"^\d+$")


def parse_retry_after(header: str) -> float:
    """
    Parse a ``Retry-After`` HTTP header value.

    Accepts either a number of seconds (``"120"``) or an HTTP-date
    (``"Wed, 21 Oct 2025 07:28:00 GMT"``).  Returns seconds to wait,
    clamped to [1, 300].
    """
    if _RETRY_AFTER_RE.match(header.strip()):
        return max(1.0, min(float(header.strip()), 300.0))

    try:
        from email.utils import parsedate_to_datetime
        target = parsedate_to_datetime(header)
        delta = (target - datetime.now(timezone.utc)).total_seconds()
        return max(1.0, min(delta, 300.0))
    except Exception:
        return 30.0   # safe default


def handle_http_rejection(
    resp: requests.Response,
    url: str,
    session: requests.Session,
    attempt: int = 0,
    max_retries: int = 2,
) -> requests.Response | None:
    """
    Handle common HTTP rejection responses and retry when appropriate.

    Supported status codes
    ~~~~~~~~~~~~~~~~~~~~~~
    * **403 Forbidden** – retry with stripped query params or alternate path.
    * **429 Too Many Requests** – honour ``Retry-After``, back off, retry.
    * **503 Service Unavailable** – back off with exponential delay, retry.
    * **401 Unauthorized** – log and skip (no credentials to provide).
    * **407 Proxy Auth Required** – log and skip.

    Returns the successful response on retry, or ``None`` if all retries
    are exhausted.
    """
    status = resp.status_code

    if attempt >= max_retries:
        log.debug("Max retries (%d) reached for %s [%d].",
                  max_retries, url, status)
        return None

    if status == 429:
        # Rate-limited – respect Retry-After
        retry_after = resp.headers.get("Retry-After", "")
        wait = parse_retry_after(retry_after) if retry_after else (2 ** attempt) * 5
        log.info("429 Too Many Requests for %s – waiting %.1fs before retry.",
                 url, wait)
        time.sleep(wait)
        try:
            retry_resp = session.get(url, timeout=REQUEST_TIMEOUT,
                                     allow_redirects=True)
            if retry_resp.status_code < 400:
                return retry_resp
            return handle_http_rejection(retry_resp, url, session,
                                         attempt + 1, max_retries)
        except requests.RequestException:
            return None

    if status == 503:
        # Service unavailable – exponential back-off
        wait = (2 ** attempt) * 3
        log.info("503 Service Unavailable for %s – retrying in %.1fs.", url, wait)
        time.sleep(wait)
        try:
            retry_resp = session.get(url, timeout=REQUEST_TIMEOUT,
                                     allow_redirects=True)
            if retry_resp.status_code < 400:
                return retry_resp
            return handle_http_rejection(retry_resp, url, session,
                                         attempt + 1, max_retries)
        except requests.RequestException:
            return None

    if status == 403:
        # Forbidden – try without query string or with trailing slash
        parsed = urllib.parse.urlparse(url)
        alt_url = None
        if parsed.query:
            alt_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        elif not parsed.path.endswith("/"):
            alt_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path + "/", "", "", ""))

        if alt_url and alt_url != url:
            log.debug("403 for %s – trying alternate URL: %s", url, alt_url)
            try:
                retry_resp = session.get(alt_url, timeout=REQUEST_TIMEOUT,
                                         allow_redirects=True)
                if retry_resp.status_code < 400:
                    return retry_resp
            except requests.RequestException:
                pass
        return None

    if status in (401, 407):
        log.debug("%d for %s – skipping (no credentials available).", status, url)
        return None

    return None


def try_alternate_scheme(
    url: str,
    session: requests.Session,
) -> requests.Response | None:
    """
    If a request to *url* failed, retry with the opposite scheme
    (HTTP ↔ HTTPS).  Returns the response or None.
    """
    parsed = urllib.parse.urlparse(url)
    alt_scheme = "http" if parsed.scheme == "https" else "https"
    alt_url = urllib.parse.urlunparse(
        (alt_scheme, parsed.netloc, parsed.path, parsed.params,
         parsed.query, ""))
    try:
        resp = session.get(alt_url, timeout=REQUEST_TIMEOUT,
                           allow_redirects=True)
        if resp.status_code < 400:
            log.debug("Alternate scheme succeeded: %s → [%d]",
                      alt_url, resp.status_code)
            return resp
    except requests.RequestException:
        pass
    return None


# ---------------------------------------------------------------------------
# Connection-reset resilience
# ---------------------------------------------------------------------------

def is_connection_reset(exc: Exception) -> bool:
    """
    Return True if *exc* (or any exception in its ``__cause__`` /
    ``__context__`` chain) is a TCP connection-reset error.

    Connection resets manifest as:
      • ``ConnectionResetError`` (errno 104 on Linux, 10054 on Windows)
      • ``BrokenPipeError``
      • urllib3 ``ProtocolError`` wrapping one of the above
      • ``requests.ConnectionError`` wrapping any of the above
      • Error messages containing "reset by peer" or "ECONNRESET"
    """
    cur: Exception | None = exc
    seen: set[int] = set()
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, (ConnectionResetError, BrokenPipeError)):
            return True
        msg = str(cur).lower()
        if "reset by peer" in msg or "econnreset" in msg or "connection reset" in msg:
            return True
        # Walk the chain
        cur = getattr(cur, "__cause__", None) or getattr(cur, "__context__", None)
    return False


def retry_on_connection_reset(
    url: str,
    session: requests.Session,
    max_retries: int = CONNECTION_RESET_MAX_RETRIES,
    verify_ssl: bool = False,
) -> requests.Response | None:
    """
    Multi-strategy retry when a connection-reset error occurs.

    Strategies applied on each successive attempt:

    1. **Exponential back-off** – wait ``2^attempt`` seconds to let the
       server recover or rate-limiter cool down.
    2. **User-Agent rotation** – switch to a different browser fingerprint
       so the server does not recognise the previous requester.
    3. **Alternate scheme** – swap HTTP ↔ HTTPS in case the reset is
       TLS-related or the server prefers plain HTTP.
    4. **Fresh session** – build a brand-new ``requests.Session`` (new TCP
       connection, clean cookie jar, fresh TLS handshake) to overcome
       server-side connection tracking.

    Returns the first successful response, or ``None`` if every strategy
    is exhausted.
    """
    for attempt in range(max_retries):
        wait = 2 ** attempt
        log.info("Connection reset for %s – retry %d/%d in %ds "
                 "(rotating UA, may swap scheme).",
                 url, attempt + 1, max_retries, wait)
        time.sleep(wait)

        # Rotate User-Agent
        ua = _ALTERNATE_USER_AGENTS[attempt % len(_ALTERNATE_USER_AGENTS)]
        session.headers["User-Agent"] = ua

        # Strategy A: retry same URL with new UA
        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT,
                               allow_redirects=True)
            if resp.status_code < 400:
                log.info("Retry %d succeeded for %s [%d].",
                         attempt + 1, url, resp.status_code)
                return resp
        except requests.RequestException as retry_exc:
            if not is_connection_reset(retry_exc):
                log.debug("Non-reset error on retry %d: %s", attempt + 1, retry_exc)

        # Strategy B: alternate scheme (HTTP ↔ HTTPS)
        alt_resp = try_alternate_scheme(url, session)
        if alt_resp is not None:
            log.info("Alternate scheme succeeded on retry %d for %s.",
                     attempt + 1, url)
            return alt_resp

        # Strategy C: fresh session (new TCP + TLS state)
        if attempt >= 1:
            log.debug("Building fresh session for retry %d.", attempt + 1)
            fresh = build_session(verify_ssl=verify_ssl)
            fresh.headers["User-Agent"] = _ALTERNATE_USER_AGENTS[
                (attempt + 1) % len(_ALTERNATE_USER_AGENTS)
            ]
            try:
                resp = fresh.get(url, timeout=REQUEST_TIMEOUT,
                                 allow_redirects=True)
                if resp.status_code < 400:
                    log.info("Fresh session succeeded on retry %d for %s [%d].",
                             attempt + 1, url, resp.status_code)
                    return resp
            except requests.RequestException:
                pass

    log.warning("All %d connection-reset retries exhausted for %s.",
                max_retries, url)
    return None

_CSS_URL_RE = re.compile(r"""url\(\s*['"]?([^)'">\s]+)['"]?\s*\)""", re.I)
_CSS_IMPORT_RE = re.compile(r"""@import\s+['"]([^'"]+)['"]""", re.I)
_ABS_QUOTED_PATH_RE = re.compile(
    r"""['"`](/[a-zA-Z0-9_./%?&=+\-#][^'"`\n]{0,200})['"`]""", re.I,
)


def normalise_url(raw: str, page_url: str, base: str) -> str | None:
    """Resolve a raw URL reference against the current page URL."""
    if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
        return None

    resolved = urllib.parse.urljoin(page_url, raw)
    parsed = urllib.parse.urlparse(resolved)

    if parsed.scheme not in ("http", "https"):
        return None

    # Only keep URLs within megared.net.mx domain
    if not parsed.netloc.endswith(BASE_DOMAIN):
        return None

    # Remove fragment
    canonical = urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params,
         parsed.query, "")
    )
    return canonical


def extract_links(content: str, page_url: str) -> set[str]:
    """Extract all links from HTML content that stay within megared.net.mx."""
    found: set[str] = set()

    try:
        soup = BeautifulSoup(content, _BS4_PARSER)
    except Exception:
        return found

    # Standard HTML tag attributes
    attr_map = {
        "a":       ["href"],
        "link":    ["href"],
        "script":  ["src"],
        "img":     ["src", "data-src"],
        "iframe":  ["src"],
        "frame":   ["src"],
        "form":    ["action"],
        "meta":    [],
        "base":    ["href"],
        "area":    ["href"],
    }
    for tag, attrs in attr_map.items():
        for el in soup.find_all(tag):
            for attr in attrs:
                val = el.get(attr)
                if val:
                    n = normalise_url(val, page_url, page_url)
                    if n:
                        found.add(n)
            if tag == "meta":
                content_attr = el.get("content", "")
                m = re.search(r"url=([^\s;\"']+)", content_attr, re.I)
                if m:
                    n = normalise_url(m.group(1), page_url, page_url)
                    if n:
                        found.add(n)

    # Inline <script> blocks – extract root-relative paths
    for script_el in soup.find_all("script"):
        if not script_el.get("src"):
            text = script_el.get_text()
            for m in _ABS_QUOTED_PATH_RE.finditer(text):
                n = normalise_url(m.group(1), page_url, page_url)
                if n:
                    found.add(n)

    # Inline <style> blocks
    for style_el in soup.find_all("style"):
        text = style_el.get_text()
        for pat in (_CSS_URL_RE, _CSS_IMPORT_RE):
            for m in pat.finditer(text):
                n = normalise_url(m.group(1), page_url, page_url)
                if n:
                    found.add(n)

    return found


def extract_title(content: str) -> str:
    """Extract <title> from HTML content."""
    try:
        soup = BeautifulSoup(content, _BS4_PARSER)
        title_tag = soup.find("title")
        if title_tag and title_tag.string:
            return title_tag.string.strip()[:200]
    except Exception:
        pass
    return ""


def is_index_file(url: str) -> bool:
    """Check if a URL points to a known index/default file."""
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.rstrip("/")
    basename = path.rsplit("/", 1)[-1].lower() if "/" in path else path.lower()

    # Direct match against known index filenames
    for idx_name in INDEX_FILENAMES:
        if basename == idx_name.lower():
            return True

    # Root path "/" is effectively an index file
    if parsed.path in ("/", ""):
        return True

    return False


# ---------------------------------------------------------------------------
# Core crawler
# ---------------------------------------------------------------------------

class MegaredCrawler:
    """
    BFS web crawler for megared.net.mx domain.

    Probes known subdomains and common paths to discover index files.
    Follows links within the megared.net.mx domain up to a configurable depth.
    """

    def __init__(
        self,
        output_dir: Path,
        max_depth: int = DEFAULT_DEPTH,
        max_pages: int = DEFAULT_MAX_PAGES,
        delay: float = DEFAULT_DELAY,
        include_ports: bool = False,
        verify_ssl: bool = False,
    ) -> None:
        self.output_dir = output_dir
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.delay = delay
        self.include_ports = include_ports
        self.session = build_session(verify_ssl=verify_ssl)

        self._visited: set[str] = set()
        self._queue: deque[tuple[str, int]] = deque()  # (url, depth)
        self._hashes: set[str] = set()
        self._pages_fetched = 0
        self.report = CrawlReport()

    def run(self) -> CrawlReport:
        """Execute the full crawl and return a report."""
        self.report.start_time = datetime.now(timezone.utc).isoformat()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        run_t0 = time.monotonic()

        log.info("=" * 60)
        log.info("Megared.net.mx Crawler & Index File Finder")
        log.info("=" * 60)
        log.info("Output directory : %s", self.output_dir.resolve())
        log.info("Max depth        : %d", self.max_depth)
        log.info("Max pages        : %d", self.max_pages)
        log.info("Delay            : %.2fs", self.delay)
        log.info("Include ports    : %s", self.include_ports)

        # Phase 1: Probe known subdomains and common paths
        log.info("-" * 60)
        log.info("Phase 1: Probing known subdomains and common paths...")
        p1_t0 = time.monotonic()
        self._probe_subdomains()
        p1_elapsed = time.monotonic() - p1_t0
        log.info("Phase 1 completed in %.1fs.", p1_elapsed)

        # Phase 2: BFS crawl from discovered pages
        log.info("-" * 60)
        log.info("Phase 2: BFS crawl (depth=%d, max=%d pages)...",
                 self.max_depth, self.max_pages)
        p2_t0 = time.monotonic()
        self._bfs_crawl()
        p2_elapsed = time.monotonic() - p2_t0
        log.info("Phase 2 completed in %.1fs.", p2_elapsed)

        # Phase 3: Generate report
        total_elapsed = time.monotonic() - run_t0
        self.report.end_time = datetime.now(timezone.utc).isoformat()
        self.report.urls_visited = len(self._visited)
        self.report.all_discovered_urls = sorted(self._visited)

        report_path = self.report.save(self.output_dir)

        log.info("-" * 60)
        log.info("Crawl complete in %.1fs!", total_elapsed)
        log.info("  Phase 1 (reachability + probing) : %.1fs", p1_elapsed)
        log.info("  Phase 2 (BFS crawl)              : %.1fs", p2_elapsed)
        log.info("  URLs visited      : %d", self.report.urls_visited)
        log.info("  Index files found  : %d", len(self.report.index_files_found))
        log.info("  Errors            : %d", len(self.report.errors))
        log.info("  Report saved to   : %s", report_path)

        self._print_index_summary()

        return self.report

    def _probe_subdomains(self) -> None:
        """Probe known subdomains with common index file paths."""
        # Pre-check which subdomains are reachable (handles ping-blocked hosts)
        reachable_hosts: dict[str, dict] = {}
        log.info("Checking reachability of %d subdomains...", len(KNOWN_SUBDOMAINS))
        t0 = time.monotonic()
        for subdomain in KNOWN_SUBDOMAINS:
            st = time.monotonic()
            info = check_host_reachable(subdomain, self.session)
            elapsed = time.monotonic() - st
            reachable_hosts[subdomain] = info
            self.report.subdomains_probed.append(subdomain)
            if info["reachable"]:
                log.info("  ✓ %s  (via %s, %.1fs)", subdomain, info["method"], elapsed)
            else:
                reason = "no DNS" if not info.get("dns", True) else "unreachable"
                log.info("  ✗ %s  (%s, %.1fs)", subdomain, reason, elapsed)
        reachability_time = time.monotonic() - t0

        reachable_count = sum(1 for h in reachable_hosts.values() if h["reachable"])
        log.info("Reachability check done: %d/%d reachable in %.1fs.",
                 reachable_count, len(KNOWN_SUBDOMAINS), reachability_time)

        # Build target URL list with deduplication
        seen_targets: set[str] = set()
        targets: list[str] = []
        for subdomain in KNOWN_SUBDOMAINS:
            if not reachable_hosts[subdomain]["reachable"]:
                continue  # skip unreachable hosts entirely

            # Prefer the scheme that worked during reachability check
            http_info = reachable_hosts[subdomain].get("http", {})
            preferred_scheme = http_info.get("scheme", "https")
            schemes = [preferred_scheme]
            alt = "http" if preferred_scheme == "https" else "https"
            schemes.append(alt)

            for scheme in schemes:
                for path in COMMON_PATHS:
                    u = f"{scheme}://{subdomain}{path}"
                    if u not in seen_targets:
                        seen_targets.add(u)
                        targets.append(u)
                for idx_file in INDEX_FILENAMES[:10]:
                    u = f"{scheme}://{subdomain}/{idx_file}"
                    if u not in seen_targets:
                        seen_targets.add(u)
                        targets.append(u)

            if self.include_ports:
                for port in EXTRA_PORTS:
                    for scheme in ("https", "http"):
                        base = f"{scheme}://{subdomain}:{port}"
                        u = f"{base}/"
                        if u not in seen_targets:
                            seen_targets.add(u)
                            targets.append(u)
                        for idx_file in INDEX_FILENAMES[:5]:
                            u = f"{base}/{idx_file}"
                            if u not in seen_targets:
                                seen_targets.add(u)
                                targets.append(u)

        log.info("Probing %d unique target URLs across %d reachable subdomains...",
                 len(targets), reachable_count)

        for url in targets:
            if self._pages_fetched >= self.max_pages:
                log.info("Max pages reached during subdomain probing.")
                break
            self._probe_url(url, depth=0)

    def _probe_url(self, url: str, depth: int) -> None:
        """Probe a single URL: check if reachable, detect index files."""
        key = self._url_key(url)
        if key in self._visited:
            return
        self._visited.add(key)

        try:
            resp = self.session.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
            self._pages_fetched += 1

            # Handle HTTP rejections (403, 429, 503) with retries
            if resp.status_code in (403, 429, 503, 401, 407):
                retry_resp = handle_http_rejection(
                    resp, url, self.session, attempt=0, max_retries=2,
                )
                if retry_resp is not None:
                    resp = retry_resp
                else:
                    log.debug("Rejected [%d] %s – no successful retry.", resp.status_code, url)
                    self.report.errors.append({
                        "url": url,
                        "error": f"HTTP {resp.status_code}",
                    })
                    if self.delay > 0:
                        time.sleep(self.delay)
                    return

            status = resp.status_code
            ct = resp.headers.get("Content-Type", "")
            cl = len(resp.content)
            server = resp.headers.get("Server", "")

            log.debug("[%d] %s  (CT=%s, %d bytes, Server=%s)",
                      status, url, ct, cl, server)

            self._process_response(resp, url, depth)

            if self.delay > 0:
                time.sleep(self.delay)

        except requests.exceptions.SSLError as exc:
            log.debug("SSL error for %s – trying alternate scheme.", url)
            alt_resp = try_alternate_scheme(url, self.session)
            if alt_resp is not None:
                self._pages_fetched += 1
                self._process_response(alt_resp, alt_resp.url, depth)
            else:
                self.report.errors.append({"url": url, "error": f"SSL: {exc}"})
        except requests.exceptions.ConnectionError as exc:
            if is_connection_reset(exc):
                log.debug("Connection reset for %s – starting multi-strategy retry.", url)
                reset_resp = retry_on_connection_reset(url, self.session)
                if reset_resp is not None:
                    self._pages_fetched += 1
                    self._process_response(reset_resp, reset_resp.url, depth)
                else:
                    self.report.errors.append({
                        "url": url, "error": f"ConnectionReset: {exc}",
                    })
            else:
                log.debug("Connection error for %s – trying alternate scheme.", url)
                alt_resp = try_alternate_scheme(url, self.session)
                if alt_resp is not None:
                    self._pages_fetched += 1
                    self._process_response(alt_resp, alt_resp.url, depth)
                else:
                    self.report.errors.append({
                        "url": url, "error": f"Connection: {exc}",
                    })
        except requests.exceptions.Timeout:
            log.debug("Timeout for %s – trying alternate scheme.", url)
            alt_resp = try_alternate_scheme(url, self.session)
            if alt_resp is not None:
                self._pages_fetched += 1
                self._process_response(alt_resp, alt_resp.url, depth)
            else:
                self.report.errors.append({"url": url, "error": "Timeout"})
        except requests.RequestException as exc:
            log.debug("Request error for %s: %s", url, exc)
            self.report.errors.append({"url": url, "error": str(exc)})

    def _process_response(
        self, resp: requests.Response, url: str, depth: int,
    ) -> None:
        """
        Process a successful HTTP response: detect index files, save content,
        and extract links for the BFS queue.

        Factored out of ``_probe_url`` so it can also be called after
        alternate-scheme fallbacks.
        """
        status = resp.status_code
        ct = resp.headers.get("Content-Type", "")
        cl = len(resp.content)
        server = resp.headers.get("Server", "")
        redirect_url = resp.url if resp.url != url else ""

        found_index = is_index_file(url)
        if redirect_url:
            found_index = found_index or is_index_file(redirect_url)

        content_text = ""
        if ct.split(";")[0].strip().lower() in CRAWLABLE_TYPES:
            content_text = resp.content.decode("utf-8", errors="replace")

        title = extract_title(content_text) if content_text else ""

        if found_index and status < 400:
            result = IndexFileResult(
                url=url,
                status_code=status,
                content_type=ct.split(";")[0].strip(),
                content_length=cl,
                server=server,
                title=title,
                redirect_url=redirect_url,
            )
            self.report.index_files_found.append(result)
            log.info("  INDEX FOUND: %s [%d] %s (%d bytes) title='%s'",
                     url, status, ct.split(";")[0].strip(), cl, title)
            self._save_content(url, resp.content, ct)

        elif status < 400 and content_text:
            self._save_content(url, resp.content, ct)

        if content_text and depth < self.max_depth:
            links = extract_links(content_text, resp.url or url)
            for link in links:
                lk = self._url_key(link)
                if lk not in self._visited:
                    self._queue.append((link, depth + 1))

    def _bfs_crawl(self) -> None:
        """Process the BFS queue, following discovered links."""
        if _TQDM_AVAILABLE and self._queue:
            bar = _tqdm(
                desc="Crawling",
                unit="URL",
                dynamic_ncols=True,
                bar_format="{l_bar}{bar}| {n}/{total} [{elapsed}] {postfix}",
            )
            bar.total = len(self._queue)
            while self._queue and self._pages_fetched < self.max_pages:
                url, depth = self._queue.popleft()
                prev_q = len(self._queue)
                self._probe_url(url, depth)
                new_items = len(self._queue) - prev_q
                if new_items > 0:
                    bar.total += new_items
                bar.update(1)
                bar.set_postfix(
                    queued=len(self._queue),
                    found=len(self.report.index_files_found),
                    fetched=self._pages_fetched,
                )
            bar.close()
        else:
            while self._queue and self._pages_fetched < self.max_pages:
                url, depth = self._queue.popleft()
                self._probe_url(url, depth)

    def _save_content(self, url: str, content: bytes, content_type: str) -> None:
        """Save downloaded content to disk mirroring the URL structure."""
        chash = hashlib.sha256(content).hexdigest()[:16]
        if chash in self._hashes:
            log.debug("Duplicate content skipped: %s", url)
            return
        self._hashes.add(chash)

        parsed = urllib.parse.urlparse(url)
        # Build local path: subdomain/path
        host_dir = parsed.netloc.replace(":", "_")
        path = parsed.path.lstrip("/")
        if not path:
            path = "index.html"
        elif path.endswith("/"):
            path += "index.html"

        local_path = self.output_dir / host_dir / Path(path)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_bytes(content)
        log.debug("Saved → %s (%d bytes)", local_path, len(content))

    def _print_index_summary(self) -> None:
        """Print a formatted summary of discovered index files."""
        if not self.report.index_files_found:
            log.info("No index files were found.")
            return

        log.info("=" * 60)
        log.info("INDEX FILES DISCOVERED:")
        log.info("=" * 60)
        for i, result in enumerate(self.report.index_files_found, 1):
            log.info(
                "  %d. %s\n"
                "     Status: %d | Type: %s | Size: %d bytes\n"
                "     Server: %s | Title: %s%s",
                i,
                result.url,
                result.status_code,
                result.content_type,
                result.content_length,
                result.server or "(unknown)",
                result.title or "(no title)",
                f"\n     Redirected to: {result.redirect_url}" if result.redirect_url else "",
            )
        log.info("=" * 60)

    @staticmethod
    def _url_key(url: str) -> str:
        """Deduplication key: scheme + host + path (no query/fragment)."""
        p = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse((p.scheme, p.netloc, p.path, "", "", ""))


# ---------------------------------------------------------------------------
# ACS endpoint firmware probing (optional --probe-acs)
# ---------------------------------------------------------------------------

def probe_acs_firmware_endpoints(output_dir: Path) -> None:
    """Probe firmware-extracted ACS endpoints for downloadable .bin files.

    Uses the ACS endpoints discovered in the EG8145V5 firmware rootfs
    (see firmware_tools/fw_analysis.py) and attempts HEAD requests with
    authentic Huawei CWMP User-Agent headers.
    """
    try:
        from firmware_tools.fw_analysis import (
            ACS_ENDPOINTS,
            FIRMWARE_FILENAMES,
            FIRMWARE_DOWNLOAD_PATHS,
            FIRMWARE_USER_AGENTS,
        )
    except ImportError:
        log.error("firmware_tools package not found — cannot probe ACS endpoints")
        return

    log.info("=" * 60)
    log.info("Phase: ACS Firmware Endpoint Probing")
    log.info(
        "Probing %d ACS endpoints × %d paths × %d filenames",
        len(ACS_ENDPOINTS), len(FIRMWARE_DOWNLOAD_PATHS),
        len(FIRMWARE_FILENAMES),
    )
    log.info("=" * 60)

    ua = FIRMWARE_USER_AGENTS.get("cwmp", "HuaweiHomeGateway")
    results: list[dict] = []
    found_count = 0

    session = requests.Session()
    session.headers.update({"User-Agent": ua})
    session.verify = False

    for ep in ACS_ENDPOINTS:
        host = ep["host"]

        # Quick DNS check
        if not dns_resolves(host):
            log.debug("DNS: %s does not resolve — skipping", host)
            continue

        port = ep["port"]
        proto = ep["protocol"]
        base = f"{proto}://{host}:{port}"

        log.info("Probing ACS: %s [%s]", base, ep.get("isp", "?"))

        for path in FIRMWARE_DOWNLOAD_PATHS:
            for fname in FIRMWARE_FILENAMES:
                url = f"{base}{path}{fname}"
                try:
                    resp = session.head(url, timeout=5, allow_redirects=True)
                    cl = resp.headers.get("Content-Length", "")
                    ct = resp.headers.get("Content-Type", "")
                    size = int(cl) if cl.isdigit() else 0

                    if resp.status_code < 400 and size > 10000:
                        found_count += 1
                        result = {
                            "url": url,
                            "status": resp.status_code,
                            "content_type": ct,
                            "content_length": size,
                            "server": resp.headers.get("Server", ""),
                            "isp": ep.get("isp", ""),
                        }
                        results.append(result)
                        log.info(
                            "  ✓ FOUND [%d] %s (%d bytes, %s)",
                            resp.status_code, url, size, ct,
                        )
                except requests.exceptions.ConnectionError:
                    break  # host not reachable, skip remaining paths
                except Exception:
                    continue

    # Save results
    report_path = output_dir / "acs_firmware_probes.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps({
            "total_endpoints": len(ACS_ENDPOINTS),
            "firmware_files_found": found_count,
            "results": results,
        }, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    log.info("-" * 60)
    log.info(
        "ACS probe complete: %d firmware files found across %d endpoints",
        found_count, len(ACS_ENDPOINTS),
    )
    log.info("Report saved to: %s", report_path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Crawl megared.net.mx (MEGACABLE ISP) and search for index files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python megared_crawler.py\n"
            "  python megared_crawler.py --depth 3 --max-pages 500\n"
            "  python megared_crawler.py --include-ports --debug\n"
        ),
    )
    parser.add_argument(
        "--output", default=DEFAULT_OUTPUT,
        help=f"Output directory (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--depth", type=int, default=DEFAULT_DEPTH,
        help=f"Maximum BFS crawl depth (default: {DEFAULT_DEPTH})",
    )
    parser.add_argument(
        "--max-pages", type=int, default=DEFAULT_MAX_PAGES,
        help=f"Maximum number of pages to fetch (default: {DEFAULT_MAX_PAGES})",
    )
    parser.add_argument(
        "--delay", type=float, default=DEFAULT_DELAY,
        help=f"Delay between requests in seconds (default: {DEFAULT_DELAY})",
    )
    parser.add_argument(
        "--include-ports", action="store_true", default=False,
        help="Also probe non-standard ports (8080, 8443, 7547, etc.)",
    )
    parser.add_argument(
        "--timeout", type=int, default=DEFAULT_TIMEOUT,
        help=f"HTTP request timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--no-verify-ssl", dest="verify_ssl", action="store_false", default=False,
        help="Disable TLS certificate verification (default: disabled)",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable verbose debug logging",
    )
    parser.add_argument(
        "--probe-acs", action="store_true", default=False,
        help="Probe firmware-extracted ACS endpoints for .bin firmware files",
    )
    return parser.parse_args()


def main() -> None:
    global REQUEST_TIMEOUT
    args = parse_args()

    _setup_logging(debug=args.debug)

    if args.debug:
        logging.getLogger("urllib3").setLevel(logging.DEBUG)

    # Apply user-specified timeout
    REQUEST_TIMEOUT = args.timeout

    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    if not _TQDM_AVAILABLE:
        log.info("Tip: install tqdm for a live progress bar  (pip install tqdm)")
    if not _COLORLOG_AVAILABLE:
        log.info("Tip: install colorlog for colored output   (pip install colorlog)")

    output_dir = Path(args.output)

    crawler = MegaredCrawler(
        output_dir=output_dir,
        max_depth=args.depth,
        max_pages=args.max_pages,
        delay=args.delay,
        include_ports=args.include_ports,
        verify_ssl=args.verify_ssl,
    )
    crawler.run()

    if args.probe_acs:
        probe_acs_firmware_endpoints(output_dir)


if __name__ == "__main__":
    main()
