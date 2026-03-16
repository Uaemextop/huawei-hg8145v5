"""
Cloudflare Managed Challenge bypass.

Provides two strategies to solve Cloudflare challenges:

1. **curl_cffi** (preferred) – impersonates a real browser TLS fingerprint
   using Chrome/Safari/Safari iOS profiles.
2. **Playwright** (fallback) – launches a headless browser (Firefox preferred,
   Chromium fallback) with webdriver flag hidden and UA rotation.

Also provides helpers to detect CF challenge pages and inject ``cf_clearance``
cookies from a real browser session.
"""

from __future__ import annotations

import logging
import random

import requests

__all__ = [
    "build_cf_session",
    "is_cf_managed_challenge",
    "inject_cf_clearance",
    "solve_cf_challenge",
]

log = logging.getLogger("crawl4ai.extensions.bypass.cloudflare")

# Import UA list from session module
from .session import USER_AGENTS

# Optional curl_cffi support
try:
    from curl_cffi import requests as _cf_requests
    _CURL_CFFI_AVAILABLE = True
except ImportError:
    _CURL_CFFI_AVAILABLE = False

# TLS impersonation profiles to try, in order of preference
_CF_IMPERSONATE_PROFILES = ["chrome", "safari", "safari_ios"]

_CF_MAX_ATTEMPTS = 3


def build_cf_session(verify_ssl: bool = True):
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
