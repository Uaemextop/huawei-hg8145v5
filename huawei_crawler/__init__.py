"""
huawei_crawler
==============
Python package for crawling and archiving all resources from a Huawei
HG8145V5 router admin panel (or any web target) to local disk.

Package structure
-----------------
huawei_crawler/
├── __init__.py       – package init and public API
├── config.py         – configuration constants
├── auth.py           – login, token refresh, session-expiry detection
├── session.py        – requests.Session factory
├── utils.py          – URL normalisation and file-path helpers
├── crawler.py        – BFS Crawler class
├── cli.py            – argparse CLI (``python -m huawei_crawler``)
└── extract/          – sub-package: link extraction from HTML / JS / CSS
    ├── __init__.py
    ├── core.py       – master dispatcher (extract_links)
    ├── html.py       – HTML attribute extraction via BeautifulSoup
    ├── js.py         – JavaScript path extraction
    └── css.py        – CSS url() / @import extraction

Quick start
-----------
    from huawei_crawler import Crawler
    from pathlib import Path

    crawler = Crawler(
        host="192.168.100.1",
        username="Mega_gpon",
        password="your_password",
        output_dir=Path("downloaded_site"),
    )
    crawler.run()
"""

from .crawler import Crawler
from .auth    import login, is_session_expired, refresh_token
from .extract import extract_links
from .utils   import normalise_url, url_key, base_url

__all__ = [
    "Crawler",
    "login",
    "is_session_expired",
    "refresh_token",
    "extract_links",
    "normalise_url",
    "url_key",
    "base_url",
]
