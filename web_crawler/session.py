"""
HTTP session creation for the generic web crawler.

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
import random
import re
import struct
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from web_crawler.config import MAX_RETRIES, USER_AGENTS

try:
    from curl_cffi import requests as _cf_requests
    _CURL_CFFI_AVAILABLE = True
except ImportError:
    _CURL_CFFI_AVAILABLE = False

# TLS impersonation profiles to try, in order of preference
_CF_IMPERSONATE_PROFILES = ["chrome", "safari", "safari_ios"]


def build_session(verify_ssl: bool = True) -> requests.Session:
    """Return a ``requests.Session`` with retry logic, keep-alive,
    randomised User-Agent, and cache-busting headers."""
    session = requests.Session()
    retry = Retry(
        total=MAX_RETRIES,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
    )
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=20,
        pool_maxsize=20,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = verify_ssl
    session.headers.update({
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Connection": "keep-alive",
    })
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
    attempts.  Includes cache-busting and Referer spoofing."""
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
        "Accept-Encoding": "gzip, deflate",
        "Cache-Control": random.choice(["no-cache", "no-store", "max-age=0"]),
        "Pragma": "no-cache",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": random.choice(["none", "same-origin", "cross-site"]),
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Connection": "keep-alive",
    }
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
    from web_crawler.utils.log import log

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
    """Return ``True`` if *resp* is a SiteGround CAPTCHA challenge page."""
    if resp.headers.get("SG-Captcha") == "challenge":
        return True
    if resp.status_code == 202 and "sgcaptcha" in resp.text[:500]:
        return True
    return False


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
      2. **Playwright** (fallback) — launches a headless Chromium
         instance with a real User-Agent, hides the ``webdriver`` flag,
         and retries with rotated UAs on failure.

    Returns ``(cookies, user_agent)`` on success or ``None``.
    """
    from web_crawler.utils.log import log

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
               "  pip install playwright && playwright install chromium")
        log.warning("[CF] %s", msg)
        return None

    ua_pool = list(USER_AGENTS)
    random.shuffle(ua_pool)

    log.info("[CF] Launching headless browser …")
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--disable-blink-features=AutomationControlled"],
            )
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
