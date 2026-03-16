"""
HTTP session builder with retry logic, User-Agent rotation, Client Hints,
and cache-busting headers.

The :func:`build_session` function returns a ``requests.Session`` pre-configured
for resilient web crawling with anti-bot-detection headers (Client Hints
required by Akamai / Imperva / Cloudflare).
"""

from __future__ import annotations

import random
import re

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

__all__ = [
    "build_session",
    "random_headers",
    "cache_bust_url",
    "USER_AGENTS",
    "MAX_RETRIES",
]

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
        connect=MAX_RETRIES,
        read=MAX_RETRIES,
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
