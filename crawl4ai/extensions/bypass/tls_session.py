"""
TLS-fingerprint-aware HTTP session with Selenium fallback.

Provides :func:`build_tls_session` which returns an HTTP session that
impersonates a real browser's TLS fingerprint using ``curl_cffi``.  When
``curl_cffi`` is not installed the function falls back to a standard
``requests.Session`` with anti-bot headers (User-Agent, Client Hints).

For JavaScript-heavy pages that need a full browser, :func:`render_page`
launches a Selenium browser (via ``seleniumbase`` UC mode) to render the
page and return the final HTML + cookies.

Session hierarchy (best → fallback):
  1. ``curl_cffi`` session (TLS fingerprint impersonation, no JS)
  2. ``requests`` session (standard, anti-bot headers)

JS rendering hierarchy:
  1. ``seleniumbase`` (undetected-chromedriver, auto TLS fingerprint)
  2. ``playwright`` (stealth mode, headless Chromium/Firefox)
"""

from __future__ import annotations

import logging
import random
import re
from typing import TYPE_CHECKING

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

if TYPE_CHECKING:
    pass

__all__ = [
    "build_tls_session",
    "render_page",
    "TLS_ENGINE",
]

log = logging.getLogger(__name__)

# ── curl_cffi availability ───────────────────────────────────────────────

try:
    from curl_cffi.requests import Session as _CfSession  # type: ignore[import-untyped]
    _CURL_CFFI_OK = True
except ImportError:
    _CURL_CFFI_OK = False

# ── seleniumbase availability ────────────────────────────────────────────

try:
    from seleniumbase import SB as _SB  # type: ignore[import-untyped]
    _SELENIUM_OK = True
except ImportError:
    _SELENIUM_OK = False

# ── Playwright availability ──────────────────────────────────────────────

try:
    from playwright.sync_api import sync_playwright as _sync_playwright
    _PLAYWRIGHT_OK = True
except ImportError:
    _PLAYWRIGHT_OK = False

# ── Report which TLS engine is in use ────────────────────────────────────

TLS_ENGINE: str = "curl_cffi" if _CURL_CFFI_OK else "requests"

# ── Shared constants ─────────────────────────────────────────────────────

MAX_RETRIES = 3

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
]

# curl_cffi impersonation profiles
_CF_PROFILES = ("chrome", "safari", "safari_ios")


def _client_hints(ua: str) -> dict[str, str]:
    """Derive Sec-CH-UA* Client Hints from a User-Agent string."""
    hints: dict[str, str] = {}
    m = re.search(r"Chrome/(\d+)", ua)
    if m:
        ver = m.group(1)
        brand = f'"Chromium";v="{ver}", "Not_A Brand";v="8"'
        if "Edg/" in ua:
            brand += f', "Microsoft Edge";v="{ver}"'
        elif "OPR/" in ua:
            brand += f', "Opera";v="{ver}"'
        else:
            brand += f', "Google Chrome";v="{ver}"'
        hints["sec-ch-ua"] = brand
    hints["sec-ch-ua-mobile"] = "?1" if "Mobile" in ua else "?0"
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


def _browser_headers(ua: str) -> dict[str, str]:
    """Full set of browser-like headers including Client Hints."""
    headers = {
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
    headers.update(_client_hints(ua))
    return headers


# ── Main API ─────────────────────────────────────────────────────────────

def build_tls_session(
    verify_ssl: bool = True,
    *,
    impersonate: str = "chrome",
) -> requests.Session:
    """Build an HTTP session with TLS fingerprint impersonation.

    When ``curl_cffi`` is available the returned session impersonates the
    given browser profile at the TLS layer (JA3/JA4 fingerprint).  This
    allows the session to pass Cloudflare, Akamai, and Imperva bot checks
    without a headless browser.

    Falls back to a standard ``requests.Session`` with anti-bot headers
    when ``curl_cffi`` is not installed.

    Parameters
    ----------
    verify_ssl:
        Whether to verify TLS certificates.
    impersonate:
        curl_cffi impersonation profile (``"chrome"``, ``"safari"``, etc.).
        Only used when ``curl_cffi`` is available.

    Returns
    -------
    requests.Session
        A configured session (either curl_cffi-backed or requests-backed).
    """
    ua = random.choice(_USER_AGENTS)

    # ── Strategy 1: curl_cffi with TLS fingerprint ───────────────────
    if _CURL_CFFI_OK:
        try:
            sess = _CfSession(impersonate=impersonate)
            sess.verify = verify_ssl
            # curl_cffi sessions are requests-compatible but we add extra
            # headers for APIs/CDNs that check beyond TLS fingerprint.
            sess.headers.update(_browser_headers(ua))
            log.debug("[TLS] Using curl_cffi session (profile=%s)", impersonate)
            return sess  # type: ignore[return-value]
        except Exception as exc:
            log.debug("[TLS] curl_cffi failed: %s — falling back to requests", exc)

    # ── Strategy 2: plain requests with anti-bot headers ─────────────
    session = requests.Session()
    retry = Retry(
        total=MAX_RETRIES,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
        connect=MAX_RETRIES,
        read=MAX_RETRIES,
    )
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=50,
        pool_maxsize=50,
        pool_block=True,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = verify_ssl
    session.headers.update(_browser_headers(ua))
    log.debug("[TLS] Using requests session (no TLS fingerprint)")
    return session


# ── JS rendering (Selenium / Playwright) ─────────────────────────────────

class _RenderedPage:
    """Result of rendering a page with a headless browser."""

    __slots__ = ("html", "cookies", "final_url")

    def __init__(self, html: str, cookies: dict[str, str], final_url: str) -> None:
        self.html = html
        self.cookies = cookies
        self.final_url = final_url


def render_page(
    url: str,
    *,
    timeout: int = 30,
    wait_seconds: float = 2.0,
) -> _RenderedPage | None:
    """Render a JavaScript-heavy page using a headless browser.

    Tries Selenium (seleniumbase UC mode) first for TLS fingerprint
    stealth, then falls back to Playwright.

    Returns a :class:`_RenderedPage` or ``None`` on failure.
    """
    # ── Strategy 1: seleniumbase UC mode ─────────────────────────────
    if _SELENIUM_OK:
        result = _render_with_selenium(url, timeout=timeout, wait_seconds=wait_seconds)
        if result is not None:
            return result
        log.debug("[RENDER] seleniumbase failed — trying Playwright")

    # ── Strategy 2: Playwright ───────────────────────────────────────
    if _PLAYWRIGHT_OK:
        return _render_with_playwright(url, timeout=timeout, wait_seconds=wait_seconds)

    log.warning(
        "[RENDER] No headless browser available. "
        "Install seleniumbase or playwright for JS rendering."
    )
    return None


def _render_with_selenium(
    url: str,
    *,
    timeout: int = 30,
    wait_seconds: float = 2.0,
) -> _RenderedPage | None:
    """Render page using seleniumbase in UC (undetected-chromedriver) mode."""
    try:
        with _SB(uc=True, headless=True, test=False) as sb:
            sb.open(url)
            sb.sleep(wait_seconds)
            html = sb.get_page_source()
            cookies = {}
            for c in sb.get_cookies():
                cookies[c["name"]] = c["value"]
            final_url = sb.get_current_url()
            log.debug("[RENDER] seleniumbase OK: %s", final_url)
            return _RenderedPage(html=html, cookies=cookies, final_url=final_url)
    except Exception as exc:
        log.debug("[RENDER] seleniumbase error: %s", exc)
        return None


def _render_with_playwright(
    url: str,
    *,
    timeout: int = 30,
    wait_seconds: float = 2.0,
) -> _RenderedPage | None:
    """Render page using Playwright headless browser."""
    try:
        with _sync_playwright() as p:
            try:
                browser = p.firefox.launch(headless=True)
            except Exception:
                browser = p.chromium.launch(
                    headless=True,
                    args=["--disable-blink-features=AutomationControlled"],
                )

            ua = random.choice(_USER_AGENTS)
            context = browser.new_context(user_agent=ua)
            page = context.new_page()
            page.add_init_script(
                "Object.defineProperty(navigator, 'webdriver', "
                "{get: () => undefined})"
            )

            try:
                page.goto(url, wait_until="domcontentloaded", timeout=timeout * 1000)
            except Exception as exc:
                log.debug("[RENDER] Playwright navigation error: %s", exc)
                context.close()
                browser.close()
                return None

            # Wait for JS to settle
            page.wait_for_timeout(int(wait_seconds * 1000))

            html = page.content()
            cookies = {c["name"]: c["value"] for c in context.cookies()}
            final_url = page.url

            context.close()
            browser.close()

            log.debug("[RENDER] Playwright OK: %s", final_url)
            return _RenderedPage(html=html, cookies=cookies, final_url=final_url)

    except Exception as exc:
        log.debug("[RENDER] Playwright error: %s", exc)
        return None
