"""
Session creation and validation helpers.
"""

import urllib.parse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from huawei_crawler.config import LOGIN_MARKERS, REQUEST_TIMEOUT


def build_session(verify_ssl: bool = True) -> requests.Session:
    """Return a ``requests.Session`` with retry logic and keep-alive."""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
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
        "Connection": "keep-alive",
        "Keep-Alive": "timeout=60, max=1000",
    })
    return session


def base_url(host: str) -> str:
    """Return the HTTP base URL for the given host."""
    return f"http://{host}"


def is_session_expired(resp: requests.Response) -> bool:
    """
    Return ``True`` only when the router has genuinely redirected to the login
    form.

    Avoids false positives from JS/CSS files that contain login marker strings
    and from non-HTML content types.

    Also detects the post-logout state where the session cookie is reset to
    ``'default'``.
    """
    cookie_val = resp.cookies.get("Cookie", "")
    if cookie_val.lower() == "default":
        return True

    final_path = urllib.parse.urlparse(resp.url).path.lower()
    if final_path in ("/index.asp", "/login.asp"):
        return True

    ct = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
    if ct and ct not in ("text/html", "application/xhtml+xml"):
        return False

    return all(marker in resp.text for marker in LOGIN_MARKERS)
