"""
crawl4ai.extensions – Capabilities ported from the web_crawler package.

These modules add specialised features that complement crawl4ai's
general-purpose async crawling engine:

* **detection** – WAF / CAPTCHA / soft-404 / WordPress fingerprinting
* **extraction** – cloud-storage link, CSS url(), JS path, JSON path extraction
* **session_helpers** – HTTP session helpers (Client Hints, SiteGround PoW, CF bypass)
* **storage** – on-disk file writing, content-hash dedup, Git integration
* **huawei_crawler** – Huawei router firmware download enumeration
* **settings** – Configuration constants & WAF signatures
* **url_utils** – URL normalisation & deduplication
* **log_utils** – Logging with ANSI colours & GitHub Actions support
"""

from .detection import detect_all  # noqa: F401
from .extraction import extract_all  # noqa: F401
from .huawei_crawler import HuaweiCrawler  # noqa: F401

__all__ = ["detect_all", "extract_all", "HuaweiCrawler"]
