"""
crawl4ai.extensions – Capabilities ported from the web_crawler package.

These modules add specialised features that complement crawl4ai's
general-purpose async crawling engine:

* **detection** – WAF / CAPTCHA / soft-404 / WordPress fingerprinting
* **extraction** – cloud-storage link, CSS url(), JS path, JSON path extraction
* **session** – HTTP session helpers (Client Hints, SiteGround PoW, CF bypass)
* **storage** – on-disk file writing, content-hash dedup, Git integration
* **huawei** – Huawei router firmware download enumeration
"""

from crawl4ai.extensions.detection import detect_all  # noqa: F401
from crawl4ai.extensions.extraction import extract_all  # noqa: F401
