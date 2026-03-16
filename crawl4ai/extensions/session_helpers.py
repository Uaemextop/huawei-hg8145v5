"""
HTTP session creation helpers ported from ``web_crawler.session.http``.

Provides sessions with:
* Automatic retry logic on 5xx errors
* User-Agent rotation
* Cache-busting headers to bypass CDN/proxy caches
* Cookie jar persistence for WAF cookie-based challenges
* SiteGround CAPTCHA (PoW) solver
* Cloudflare bypass via ``curl_cffi`` TLS fingerprint impersonation
"""

import base64
import hashlib
import logging
import random
import re
import struct
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

__all__ = [
    "build_session",
    "build_cf_session",
    "random_headers",
    "cache_bust_url",
    "solve_sg_pow",
    "solve_sg_captcha",
    "is_sg_captcha_response",
    "is_s3_access_denied",
    "is_tomcat_ip_restricted",
    "is_cf_managed_challenge",
    "inject_cf_clearance",
    "solve_cf_challenge",
]

log = logging.getLogger("crawl4ai.extensions.session")

# ---------------------------------------------------------------------------
# Inlined constants (originally from web_crawler.config.settings)
# ---------------------------------------------------------------------------

MAX_RETRIES = 3

USER_AGENTS = [
    # Chrome (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    # Chrome (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    # Chrome (Linux)
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    # Firefox (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    # Firefox (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    # Firefox (Linux)
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    # Safari (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    # Edge (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    # Chrome (Android)
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    # Safari (iPhone)
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
    # Opera (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/114.0.0.0",
]

# ---------------------------------------------------------------------------
# Optional curl_cffi support
# ---------------------------------------------------------------------------

try:
    from curl_cffi import requests as _cf_requests
    _CURL_CFFI_AVAILABLE = True
except ImportError:
    _CURL_CFFI_AVAILABLE = False

# TLS impersonation profiles to try, in order of preference
_CF_IMPERSONATE_PROFILES = ["chrome", "safari", "safari_ios"]


def _client_hints_for_ua(ua: str) -> dict[str, str]:
    """Derive Client Hints headers from a User-Agent string.

    Modern Akamai / Cloudflare / Imperva bot-detection checks for the
    presence of ``sec-ch-ua*`` headers that real browsers send.  Without
    them the request fingerprint looks like a plain HTTP client.
    """
    hints: dict[str, str] = {}
    m = re.search(r"Chrome/(\d+)", ua)
    if m:
        ver = m.group(1)
        brand = '"Chromium";v="{v}", "Not_A Brand";v="8"'.format(v=ver)
        if "Edg/" in ua:
            brand += ', "Microsoft Edge";v="{v}"'.format(v=ver)
        elif "OPR/" in ua:
            brand += ', "Opera";v="{v}"'.format(v=ver)
        else:
            brand += ', "Google Chrome";v="{v}"'.format(v=ver)
        hints["sec-ch-ua"] = brand
    # Mobile flag
    hints["sec-ch-ua-mobile"] = "?1" if "Mobile" in ua else "?0"
    # Platform — order matters: iPhone/iPad must precede "Mac OS" match
    if "iPhone" in ua or "iPad" in ua:
        hints["sec-ch-ua-platform"] = '"iOS"'
    elif "Windows" in ua:
        hints["sec-ch-ua-platform"] = '"Windows"'
    elif "Android" in ua:
        hints["sec-ch-ua-platform"] = '"Android"'
    elif "Macintosh" in ua or "Mac OS" in ua:
        hints["sec-ch-ua-platform"] = '"macOS"'
    elif "Linux" in ua:
        hints["sec-ch-ua-platform"] = '"Linux"'
    else:
        hints["sec-ch-ua-platform"] = '""'
    return hints


def build_session(verify_ssl: bool = True) -> requests.Session:
    """Return a ``requests.Session`` with retry logic, keep-alive,
    randomised User-Agent, cache-busting headers, and Client Hints
    derived from the chosen User-Agent (required by Akamai and similar
    bot-detection systems)."""
    session = requests.Session()
    retry = Retry(
        total=MAX_RETRIES,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
        connect=MAX_RETRIES,           # retry on connection errors
        read=MAX_RETRIES,              # retry on read errors (socket reset, etc.)
    )
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=20,
        pool_maxsize=20,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = verify_ssl
    ua = random.choice(USER_AGENTS)
    headers: dict[str, str] = {
        "User-Agent": ua,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Connection": "keep-alive",
    }
    headers.update(_client_hints_for_ua(ua))
    session.headers.update(headers)
    return session


def build_cf_session(verify_ssl: bool = True) -> "_cf_requests.Session | None":
    """Return a ``curl_cffi`` session with Chrome TLS impersonation.

    This session bypasses Cloudflare Managed Challenges by
    impersonating a real browser's TLS fingerprint.

    Returns ``None`` if ``curl_cffi`` is not installed.
    """
    if not _CURL_CFFI_AVAILABLE:
        return None
    session = _cf_requests.Session(impersonate="chrome")
    session.verify = verify_ssl
    return session


def random_headers(base_url: str = "") -> dict[str, str]:
    """Return a set of randomised browser headers for retry / bypass
    attempts.  Includes cache-busting, Referer spoofing, and Client
    Hints (required by Akamai / Imperva bot-detection)."""
    ua = random.choice(USER_AGENTS)
    headers: dict[str, str] = {
        "User-Agent": ua,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8"
        ),
        "Accept-Language": random.choice([
            "en-US,en;q=0.9",
            "en-US,en;q=0.9,es;q=0.8",
            "es-MX,es;q=0.9,en;q=0.8",
            "en-GB,en;q=0.9",
        ]),
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": random.choice(["no-cache", "no-store", "max-age=0"]),
        "Pragma": "no-cache",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": random.choice(["none", "same-origin", "cross-site"]),
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Connection": "keep-alive",
    }
    headers.update(_client_hints_for_ua(ua))
    if base_url:
        headers["Referer"] = base_url
        headers["Origin"] = base_url
    return headers


def cache_bust_url(url: str) -> str:
    """Append a random query parameter to *url* to bypass CDN/proxy
    caches.  Preserves existing query strings."""
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}_cb={random.randint(100000, 999999)}"


# ---------------------------------------------------------------------------
# SiteGround CAPTCHA (Proof-of-Work) solver
# ---------------------------------------------------------------------------

_SG_CHALLENGE_RE = re.compile(r'const\s+sgchallenge\s*=\s*"([^"]+)"')
_SG_SUBMIT_RE = re.compile(r'const\s+sgsubmit_url\s*=\s*"([^"]+)"')
_SG_MAX_ATTEMPTS = 10_000_000


def _counter_to_bytes(c: int) -> bytes:
    """Encode *c* as big-endian minimal-length bytes (matches SG JS)."""
    if c == 0:
        return b"\x00"
    if c > 0xFFFFFF:
        return c.to_bytes(4, "big")
    if c > 0xFFFF:
        return c.to_bytes(3, "big")
    if c > 0xFF:
        return c.to_bytes(2, "big")
    return c.to_bytes(1, "big")


def solve_sg_pow(challenge: str) -> tuple[str, int] | None:
    """Solve a SiteGround Proof-of-Work challenge.

    *challenge* is the value of ``sgchallenge`` from the captcha page
    (e.g. ``"20:timestamp:token:hash:"``).

    Returns ``(base64_solution, counter)`` on success or ``None``.
    """
    try:
        complexity = int(challenge.split(":")[0])
    except (ValueError, IndexError):
        return None
    if complexity < 1 or complexity > 32:
        return None

    challenge_bytes = challenge.encode("utf-8")
    for c in range(_SG_MAX_ATTEMPTS):
        data = challenge_bytes + _counter_to_bytes(c)
        h = hashlib.sha1(data).digest()
        first_word = struct.unpack(">I", h[:4])[0]
        if first_word >> (32 - complexity) == 0:
            return base64.b64encode(data).decode(), c
    return None


def solve_sg_captcha(
    session: requests.Session,
    base_url: str,
    target_path: str = "/",
    timeout: int = 30,
) -> bool:
    """Fetch a SiteGround captcha page, solve the PoW, and submit
    the solution so the session cookie is set for future requests.

    Returns ``True`` if the captcha was solved and the cookie was set.
    """
    quoted_path = requests.utils.quote(target_path, safe="/")
    captcha_url = (
        f"{base_url}/.well-known/sgcaptcha/"
        f"?r={quoted_path}&y=pow"
    )
    try:
        resp = session.get(captcha_url, timeout=timeout)
    except requests.RequestException:
        return False

    if resp.status_code != 200:
        return False

    cm = _SG_CHALLENGE_RE.search(resp.text)
    sm = _SG_SUBMIT_RE.search(resp.text)
    if not cm or not sm:
        return False

    challenge = cm.group(1)
    submit_path = sm.group(1)
    log.info("[SG-CAPTCHA] Solving PoW (complexity %s) …",
             challenge.split(":")[0])

    t0 = time.time()
    result = solve_sg_pow(challenge)
    if result is None:
        log.warning("[SG-CAPTCHA] Failed to solve PoW")
        return False

    solution, counter = result
    elapsed_ms = int((time.time() - t0) * 1000)
    log.info("[SG-CAPTCHA] Solved in %d ms (counter=%d)", elapsed_ms, counter)

    submit_url = f"{base_url}{submit_path}"
    sep = "&" if "?" in submit_url else "?"
    submit_url += (
        f"{sep}sol={requests.utils.quote(solution)}"
        f"&s={elapsed_ms}:{counter}"
    )
    try:
        session.get(submit_url, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return False

    has_cookie = any("_I_" in c.name for c in session.cookies)
    if has_cookie:
        log.info("[SG-CAPTCHA] Bypass cookie obtained")
    return has_cookie


def is_sg_captcha_response(resp: requests.Response) -> bool:
    """Return ``True`` if *resp* is a SiteGround CAPTCHA challenge page.

    Detects three variants:
    * ``SG-Captcha: challenge`` response header (canonical marker)
    * HTTP 202 with ``sgcaptcha`` in the first 500 bytes (inline challenge)
    * Any status with ``/.well-known/captcha/`` or ``sgcaptcha`` in the
      first 2 KB (SiteGround redirects / WAF-level block with CAPTCHA body)
    """
    if resp.headers.get("SG-Captcha") == "challenge":
        return True
    # Avoid buffering large binary responses – only inspect small bodies
    ct = resp.headers.get("Content-Type", "")
    if "html" not in ct.lower() and resp.status_code not in (202, 403):
        return False
    snippet = resp.text[:2000].lower()
    if "sgcaptcha" in snippet:
        return True
    if "/.well-known/captcha/" in snippet or "/.well-known/sgcaptcha/" in snippet:
        return True
    return False


# ---------------------------------------------------------------------------
# Amazon S3 / CloudFront private-bucket detection
# ---------------------------------------------------------------------------

def is_s3_access_denied(resp: requests.Response) -> bool:
    """Return ``True`` if *resp* is an Amazon S3 ``AccessDenied`` error.

    Private S3 buckets (with Block Public Access enabled) return HTTP 403
    with ``server: AmazonS3`` and an XML body whose root element is
    ``<Error><Code>AccessDenied</Code>…</Error>``.  This block is enforced
    at the bucket-policy / account level and **cannot be bypassed** by any
    HTTP header, credential, or URL trick from an external, unauthenticated
    client.  Detecting it immediately lets the crawler skip pointless
    header-rotation retries and record the XML response body for the archive.
    """
    if resp.status_code != 403:
        return False
    server = resp.headers.get("server", "") or resp.headers.get("Server", "")
    if "amazons3" not in server.lower():
        return False
    ct = resp.headers.get("Content-Type", resp.headers.get("content-type", ""))
    if "xml" not in ct.lower():
        return False
    snippet = resp.text[:512]
    return "<Code>AccessDenied</Code>" in snippet or "AccessDenied" in snippet


# ---------------------------------------------------------------------------
# Apache Tomcat IP-restriction detection
# ---------------------------------------------------------------------------

_TOMCAT_IP_RESTRICTED_PHRASES = (
    "only accessible from a browser running on the same machine as tomcat",
    "by default the documentation web application is only accessible",
    "by default the manager is only accessible",
    "by default the host manager is only accessible",
    "by default the examples web application is only accessible",
)


def is_tomcat_ip_restricted(resp: requests.Response) -> bool:
    """Return ``True`` if *resp* is a Tomcat IP-restriction 403 page.

    Tomcat's documentation, examples, manager, and host-manager web
    applications are restricted to localhost by default.  The response body
    contains a distinctive phrase that identifies this type of block, which
    cannot be bypassed by header rotation or cookie injection from an external
    IP.  Detecting it early lets the crawler skip pointless retries and record
    the page body for the crawl archive.
    """
    if resp.status_code not in (403, 401):
        return False
    ct = resp.headers.get("Content-Type", "")
    if "html" not in ct.lower():
        return False
    snippet = resp.text[:3000].lower()
    return any(phrase in snippet for phrase in _TOMCAT_IP_RESTRICTED_PHRASES)


# ---------------------------------------------------------------------------
# Cloudflare Managed Challenge detection
# ---------------------------------------------------------------------------

def is_cf_managed_challenge(resp: requests.Response) -> bool:
    """Return ``True`` if *resp* is a Cloudflare Managed Challenge page.

    Indicators:
    * ``cf-mitigated: challenge`` response header
    * HTTP 403 with ``<title>Just a moment...</title>`` in body
    * Body contains ``_cf_chl_opt`` with ``cType.*managed``
    """
    if resp.headers.get("cf-mitigated", "").lower() == "challenge":
        return True
    if resp.status_code == 403:
        snippet = resp.text[:2048].lower()
        if "just a moment" in snippet and "_cf_chl_opt" in snippet:
            return True
    return False


def inject_cf_clearance(
    session: requests.Session,
    domain: str,
    cf_clearance: str,
) -> None:
    """Inject a ``cf_clearance`` cookie into *session* for *domain*.

    The cookie must be obtained from a real browser that has solved the
    Cloudflare challenge.  Pass it via ``--cf-clearance <value>``.
    """
    session.cookies.set(
        "cf_clearance",
        cf_clearance,
        domain=domain,
        path="/",
    )


_CF_MAX_ATTEMPTS = 3


def solve_cf_challenge(
    url: str,
    timeout: int = 30,
) -> tuple[dict[str, str], str] | None:
    """Solve a Cloudflare Managed Challenge.

    Strategy:
      1. **curl_cffi** (preferred) — impersonates a real browser TLS
         fingerprint.  Tries multiple profiles (Chrome, Safari).
      2. **Playwright** (fallback) — launches a headless browser (Firefox
         preferred, Chromium fallback) with a real User-Agent, hides the
         ``webdriver`` flag, and retries with rotated UAs on failure.

    Returns ``(cookies, user_agent)`` on success or ``None``.
    """
    # ── Strategy 1: curl_cffi TLS impersonation ──────────────────
    if _CURL_CFFI_AVAILABLE:
        for profile in _CF_IMPERSONATE_PROFILES:
            log.info("[CF] Trying curl_cffi profile '%s' …", profile)
            try:
                sess = _cf_requests.Session(impersonate=profile)
                resp = sess.get(url, allow_redirects=True, timeout=timeout)
                if resp.ok and "just a moment" not in resp.text[:2048].lower():
                    ua = (resp.request.headers.get("User-Agent")  # type: ignore[union-attr]
                          if hasattr(resp, "request") and resp.request
                          else random.choice(USER_AGENTS))
                    cookie_dict = dict(sess.cookies)
                    log.info("[CF] Bypass OK with profile '%s'", profile)
                    return (cookie_dict, ua)
            except Exception as exc:
                log.debug("[CF] curl_cffi/%s failed: %s", profile, exc)
        log.info("[CF] curl_cffi profiles exhausted – trying Playwright …")

    # ── Strategy 2: Playwright headless browser ──────────────────
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        msg = ("curl_cffi and Playwright are both unavailable. "
               "Install one of them:\n"
               "  pip install curl_cffi          (recommended)\n"
               "  pip install playwright && playwright install chromium firefox")
        log.warning("[CF] %s", msg)
        return None

    ua_pool = list(USER_AGENTS)
    random.shuffle(ua_pool)

    log.info("[CF] Launching headless browser …")
    try:
        with sync_playwright() as p:
            # Try Firefox first — different TLS fingerprint, less likely
            # to be blocked by Cloudflare / Akamai bot detection.
            try:
                browser = p.firefox.launch(headless=True)
                log.info("[CF] Using Firefox browser engine")
            except Exception:
                browser = p.chromium.launch(
                    headless=True,
                    args=["--disable-blink-features=AutomationControlled"],
                )
                log.info("[CF] Using Chromium browser engine "
                         "(Firefox unavailable)")
            for attempt in range(1, _CF_MAX_ATTEMPTS + 1):
                ua = ua_pool[(attempt - 1) % len(ua_pool)]
                log.info("[CF] Attempt %d/%d  UA: %s…",
                         attempt, _CF_MAX_ATTEMPTS, ua[:50])

                context = browser.new_context(user_agent=ua)
                page = context.new_page()
                page.add_init_script(
                    "Object.defineProperty(navigator, 'webdriver', "
                    "{get: () => undefined})"
                )

                try:
                    page.goto(url, wait_until="domcontentloaded",
                              timeout=timeout * 1000)
                except Exception as exc:
                    log.debug("[CF] Navigation error: %s", exc)
                    context.close()
                    continue

                title = page.title()
                if title == "Just a moment...":
                    log.info("[CF] Challenge page – waiting …")
                    try:
                        page.wait_for_function(
                            "() => document.title !== 'Just a moment...'",
                            timeout=timeout * 1000,
                        )
                    except Exception:
                        log.warning("[CF] Attempt %d timed out", attempt)
                        context.close()
                        continue

                page.wait_for_timeout(2000)
                cookies = context.cookies()
                cookie_dict: dict[str, str] = {
                    c["name"]: c["value"] for c in cookies
                }
                context.close()

                if not cookie_dict:
                    log.debug("[CF] Attempt %d: no cookies", attempt)
                    continue

                log.info("[CF] Solved on attempt %d (%d cookies)",
                         attempt, len(cookie_dict))
                browser.close()
                return (cookie_dict, ua)

            browser.close()
            log.warning("[CF] All %d attempts failed", _CF_MAX_ATTEMPTS)
            return None
    except Exception as exc:
        log.warning("[CF] Playwright error: %s", exc)
        return None
