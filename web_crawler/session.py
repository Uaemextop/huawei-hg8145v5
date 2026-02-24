"""
HTTP session creation for the generic web crawler.
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from web_crawler.config import MAX_RETRIES


def build_session(verify_ssl: bool = True) -> requests.Session:
    """Return a ``requests.Session`` with retry logic and keep-alive."""
    session = requests.Session()
    retry = Retry(
        total=MAX_RETRIES,
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
    })
    return session
