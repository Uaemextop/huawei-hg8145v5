"""HTTP session management for the Huawei HG8145V5 crawler."""

import sys

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    sys.exit("Missing dependency. Run:  pip install -r requirements.txt")

try:
    from bs4 import BeautifulSoup  # noqa: F401 – re-exported for other modules
except ImportError:
    sys.exit("Missing dependency. Run:  pip install -r requirements.txt")

try:
    import lxml  # noqa: F401 – used as BeautifulSoup parser backend
    _BS4_PARSER = "lxml"
except ImportError:
    _BS4_PARSER = "html.parser"


def build_session(verify_ssl: bool = True) -> requests.Session:
    """Return a requests.Session with retry logic and keep-alive pre-configured."""
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
    # Mimic a real browser so the router does not reject requests based on
    # User-Agent.  Also request keep-alive to reuse the TCP connection.
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
    return f"http://{host}"
