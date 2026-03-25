"""WAF / protection detection, Cloudflare bypass, and soft-404 helpers.

Standalone functions extracted from :class:`crawl4ai.extensions.crawler.engine.Crawler`
so they can be reused and tested independently.
"""

from __future__ import annotations

import random
import re
import string
import time
import urllib.parse
from typing import TYPE_CHECKING

import requests

try:
    from curl_cffi.requests.exceptions import (
        RequestException as CfRequestException,
    )
except ImportError:
    CfRequestException = None  # type: ignore[misc,assignment]

# Network exception tuple that catches both requests and curl_cffi errors.
_NETWORK_ERRORS: tuple[type[Exception], ...] = (requests.RequestException,)
if CfRequestException is not None:
    _NETWORK_ERRORS = (requests.RequestException, CfRequestException)

from crawl4ai.extensions.settings import (
    BACKOFF_429_BASE,
    BACKOFF_429_MAX,
    HEADER_RETRY_MAX,
    REQUEST_TIMEOUT,
    SOFT_404_KEYWORDS,
    SOFT_404_MIN_KEYWORD_HITS,
    SOFT_404_SIZE_RATIO,
    SOFT_404_STANDALONE_MIN_HITS,
    SOFT_404_TITLE_KEYWORDS,
    WAF_SIGNATURES,
)
from crawl4ai.extensions.bypass.session import random_headers, cache_bust_url
from crawl4ai.extensions.bypass.cloudflare import (
    build_cf_session,
    is_cf_managed_challenge,
    solve_cf_challenge,
)
from crawl4ai.extensions.bypass.siteground import solve_sg_captcha, is_sg_captcha_response
from crawl4ai.extensions.storage import content_hash
from crawl4ai.extensions.log_utils import log

if TYPE_CHECKING:
    from crawl4ai.extensions.crawler.engine import Crawler

# ---------------------------------------------------------------------------
# Module-level constant
# ---------------------------------------------------------------------------

# Headers that indicate CDN / infrastructure metadata, not WAF blocking.
# Including them in detection causes false positives on every page served
# through a CDN (e.g. Akamai, Cloudflare) because the header names or
# values innocuously contain WAF-signature substrings.
DETECTION_EXCLUDED_HEADERS: frozenset[str] = frozenset({
    "permissions-policy",      # declares allowed feature origins
    "server",                  # CDN / web-server software identifier
    "x-akamai-transformed",    # Akamai content-transformation info
    "akamai-grn",              # Akamai Ghost Reference Number (tracking)
    "x-akamai-request-id",     # Akamai per-request tracing
    "x-akamai-session-info",   # Akamai session metadata
})

# ---------------------------------------------------------------------------
# WAF / protection detection
# ---------------------------------------------------------------------------


def detect_protection(
    headers: dict[str, str],
    body: str,
    excluded_headers: frozenset[str] = DETECTION_EXCLUDED_HEADERS,
) -> list[str]:
    """Return a list of detected WAF/protection names from *headers* and
    *body* content.

    Only the first 8 KB of the body is inspected.  Real challenge /
    CAPTCHA pages are small and put indicators near the top, while
    large content pages may mention "captcha" or "cloudflare" deep
    in plugin configuration strings, causing false positives.
    """
    filtered = {
        k: v for k, v in headers.items() if k.lower() not in excluded_headers
    }
    combined = " ".join(f"{k}: {v}" for k, v in filtered.items()).lower()
    combined += " " + body[:8192].lower()
    detected: list[str] = []
    for name, sigs in WAF_SIGNATURES.items():
        if any(s in combined for s in sigs):
            detected.append(name)
    return detected


# ---------------------------------------------------------------------------
# Header-rotation retry for 403 / 402
# ---------------------------------------------------------------------------


def retry_with_headers(
    crawler: Crawler, url: str
) -> requests.Response | None:
    """Retry *url* up to ``HEADER_RETRY_MAX`` times with different header
    profiles, cache-busted URLs, and Cloudflare-aware techniques.

    Returns a successful response or ``None``.
    """
    for attempt in range(1, HEADER_RETRY_MAX + 1):
        hdrs = random_headers(crawler.base)
        bust_url = cache_bust_url(url)
        try:
            resp = crawler.session.get(
                bust_url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                headers=hdrs,
            )
            if resp.ok and not is_sg_captcha_response(resp):
                log.debug(
                    "  [RETRY %d/%d] OK for %s (UA: %s…)",
                    attempt,
                    HEADER_RETRY_MAX,
                    url,
                    hdrs["User-Agent"][:40],
                )
                crawler._stats["retry_ok"] += 1
                return resp
            # Cloudflare cookie-based challenge: first request sets
            # cf_clearance cookie, second request should succeed.
            if not crawler._cf_bypass_done and resp.status_code == 403:
                cf_cookies = {
                    c.name
                    for c in crawler.session.cookies
                    if "cf" in c.name.lower() or "clearance" in c.name.lower()
                }
                if cf_cookies:
                    crawler._cf_bypass_done = True
                    log.debug(
                        "  Cloudflare cookies found (%s), retrying",
                        ", ".join(cf_cookies),
                    )
                    time.sleep(crawler.delay * 2)
                    resp2 = crawler.session.get(
                        url,
                        timeout=REQUEST_TIMEOUT,
                        allow_redirects=True,
                        headers=hdrs,
                    )
                    if resp2.ok:
                        crawler._stats["retry_ok"] += 1
                        log.debug("  [CF-BYPASS] Succeeded for %s", url)
                        return resp2
            log.debug(
                "  [RETRY %d/%d] HTTP %s for %s",
                attempt,
                HEADER_RETRY_MAX,
                resp.status_code,
                url,
            )
        except _NETWORK_ERRORS as exc:
            log.debug("  [RETRY %d/%d] Network error for %s: %s", attempt, HEADER_RETRY_MAX, url, exc)
        time.sleep(crawler.delay * attempt)
    return None


# ---------------------------------------------------------------------------
# 429 exponential backoff
# ---------------------------------------------------------------------------


def handle_rate_limit(
    crawler: Crawler, resp: requests.Response, url: str
) -> None:
    """Sleep with exponential backoff when a 429 is received."""
    retry_after = resp.headers.get("Retry-After")
    if retry_after and retry_after.isdigit():
        wait = min(int(retry_after), BACKOFF_429_MAX)
    else:
        wait = BACKOFF_429_BASE
    log.warning("  [429] Rate limited on %s – sleeping %.1f s", url, wait)
    time.sleep(wait)


# ---------------------------------------------------------------------------
# Cloudflare / SiteGround bypass
# ---------------------------------------------------------------------------


def check_cf_managed_challenge(crawler: Crawler) -> None:
    """Detect and auto-solve a Cloudflare Managed Challenge.

    If the site returns ``cf-mitigated: challenge``, attempt to solve it by
    switching to a ``curl_cffi`` session (TLS fingerprint impersonation) or
    falling back to Playwright.
    """
    try:
        resp = crawler.session.get(
            crawler.start_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
    except _NETWORK_ERRORS as exc:
        log.warning("[CF] Could not reach %s to check for challenge: %s", crawler.start_url, exc)
        return
    if not is_cf_managed_challenge(resp):
        log.info("No Cloudflare challenge detected")
        return

    log.warning(
        "Cloudflare Managed Challenge detected on %s",
        crawler.start_url,
    )
    solve_cf_and_inject(crawler)


def solve_cf_and_inject(crawler: Crawler) -> bool:
    """Switch the session to bypass Cloudflare.

    Uses ``curl_cffi`` TLS impersonation (preferred) or Playwright headless
    browser (fallback).  When ``curl_cffi`` works, the entire
    ``crawler.session`` is replaced with a ``curl_cffi`` session so that all
    subsequent requests use the same TLS fingerprint.

    Returns ``True`` on success.
    """
    cf_session = build_cf_session(verify_ssl=crawler.session.verify)
    if cf_session is not None:
        # Transfer existing cookies to the new session.
        for cookie in crawler.session.cookies:
            cf_session.cookies.set(
                cookie.name,
                cookie.value,
                domain=cookie.domain,
                path=cookie.path,
            )
        try:
            check = cf_session.get(
                crawler.start_url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
            if check.ok and "just a moment" not in check.text[:2048].lower():
                crawler.session = cf_session
                log.info("[CF] Switched to curl_cffi session – bypass confirmed")
                crawler._cf_bypass_done = True
                return True
        except Exception as exc:
            log.debug("[CF] curl_cffi direct attempt failed: %s", exc)

    # Fallback: Playwright + cookie injection
    result = solve_cf_challenge(crawler.start_url)
    if not result:
        log.warning(
            "[CF] Could not auto-solve. Provide --cf-clearance <cookie> "
            "obtained from a browser session to bypass it.",
        )
        return False

    cookies, browser_ua = result
    parsed = urllib.parse.urlparse(crawler.start_url)
    for name, value in cookies.items():
        crawler.session.cookies.set(
            name, value, domain=parsed.netloc, path="/"
        )
    crawler.session.headers["User-Agent"] = browser_ua
    log.info(
        "[CF] %d cookies injected (UA synced) – verifying …", len(cookies)
    )
    try:
        check = crawler.session.get(
            crawler.start_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
        if check.ok and not is_cf_managed_challenge(check):
            log.info("[CF] Cloudflare bypass confirmed")
            crawler._cf_bypass_done = True
            return True
    except _NETWORK_ERRORS as exc:
        log.warning("[CF] Verification request failed: %s", exc)
    log.warning("[CF] Cookies did not bypass the challenge")
    return False


def try_sg_captcha_bypass(crawler: Crawler) -> None:
    """If the target uses SiteGround CAPTCHA, solve the PoW challenge once
    so the session cookie is set."""
    log.info("Checking for SiteGround CAPTCHA …")
    solved = solve_sg_captcha(crawler.session, crawler.base, "/")
    if solved:
        # The server's meta-refresh suggests a 1-second wait
        # before the cookie is fully active.
        time.sleep(1)
        log.info("[SG-CAPTCHA] Solved – session cookie set")
    else:
        log.info("No SiteGround CAPTCHA detected (or not solvable)")


# ---------------------------------------------------------------------------
# Soft-404 detection
# ---------------------------------------------------------------------------


def build_soft404_fingerprint(crawler: Crawler) -> None:
    """Fetch a random non-existent URL to fingerprint the server's custom
    error page (soft-404)."""
    slug = "".join(random.choices(string.ascii_lowercase, k=12))
    probe = f"{crawler.base}/_{slug}_does_not_exist_{slug}.html"
    try:
        resp = crawler.session.get(
            probe, timeout=REQUEST_TIMEOUT, allow_redirects=True
        )
    except _NETWORK_ERRORS:
        log.debug("Soft-404 probe failed (request error); detection disabled.")
        return

    if not resp.ok:
        # Server returns a real HTTP 404 – no soft-404 problem.
        log.debug(
            "Server returns HTTP %s for missing pages – no soft-404.",
            resp.status_code,
        )
        return

    # Server returned 200 for a non-existent page – soft-404 likely.
    body = resp.content
    crawler._soft404_size = len(body)
    crawler._soft404_hash = content_hash(body)
    log.info(
        "Soft-404 baseline: %d bytes, hash=%s (server returns 200 for missing pages)",
        crawler._soft404_size,
        crawler._soft404_hash,
    )


def is_soft_404(crawler: Crawler, content: bytes, url: str) -> bool:
    """Return ``True`` if *content* looks like a soft-404 (false positive).

    Detection layers:

    1. Exact hash match with the baseline probe.
    2. Size-based heuristic + keyword check (when baseline exists).
    3. ``<title>`` tag contains 404-related keywords.
    4. Standalone keyword check (works even without baseline).
    """
    text = content.decode("utf-8", errors="replace").lower()

    # --- Layer 1: baseline fingerprint exact match ---
    if crawler._soft404_hash is not None:
        if content_hash(content) == crawler._soft404_hash:
            log.debug("  Soft-404 (exact baseline match): %s", url)
            return True

        # --- Layer 2: size similarity + keywords ---
        size = len(content)
        if crawler._soft404_size and crawler._soft404_size > 0:
            ratio = abs(size - crawler._soft404_size) / crawler._soft404_size
            if ratio <= SOFT_404_SIZE_RATIO:
                hits = sum(1 for kw in SOFT_404_KEYWORDS if kw in text)
                if hits >= SOFT_404_MIN_KEYWORD_HITS:
                    log.debug(
                        "  Soft-404 (size+keywords, %d hits): %s",
                        hits,
                        url,
                    )
                    return True

    # --- Layer 3: <title> tag contains 404-like keywords ---
    # Search only the first 4 KB where <title> typically appears.
    head = text[:4096]
    title_match = re.search(r"<title[^>]*>(.*?)</title>", head, re.S)
    if title_match:
        title = title_match.group(1).strip()
        for kw in SOFT_404_TITLE_KEYWORDS:
            if kw in title:
                log.debug(
                    "  Soft-404 (title contains '%s'): %s",
                    kw,
                    url,
                )
                return True

    # --- Layer 4: standalone keyword check (no baseline needed) ---
    hits = sum(1 for kw in SOFT_404_KEYWORDS if kw in text)
    if hits >= SOFT_404_STANDALONE_MIN_HITS:
        log.debug(
            "  Soft-404 (standalone, %d keyword hits): %s", hits, url
        )
        return True

    return False
