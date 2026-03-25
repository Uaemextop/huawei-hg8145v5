"""
crawl4ai.extensions – Specialised crawling, detection, and bypass modules.

These modules add specialised features that complement crawl4ai's
general-purpose async crawling engine:

Crawler (``crawler/``):

* :mod:`crawler.engine` – BFS web crawler (Crawler class)
* :mod:`crawler.cli` – Command-line interface
* :mod:`crawler.wordpress` – WordPress discovery & deep crawl
* :mod:`crawler.protection` – WAF/protection detection & bypass
* :mod:`crawler.media` – Video/CDN/media handling
* :mod:`crawler.git_ops` – Git integration

Detection (individual modules in ``detection/``):

* :mod:`detection.cloudflare` – Cloudflare Managed Challenge / Turnstile
* :mod:`detection.siteground` – SiteGround Security CAPTCHA (PoW)
* :mod:`detection.waf` – Generic WAF signature scanner
* :mod:`detection.soft404` – Soft-404 page detection
* :mod:`detection.wordpress` – WordPress fingerprinting
* :mod:`detection.captcha` – CAPTCHA embed detection (reCAPTCHA, hCAPTCHA, …)

Bypass / correction (individual modules in ``bypass/``):

* :mod:`bypass.session` – HTTP session builder (retry, UA rotation, Client Hints)
* :mod:`bypass.cloudflare` – CF challenge solver (curl_cffi + Playwright)
* :mod:`bypass.siteground` – SiteGround PoW CAPTCHA solver
* :mod:`bypass.s3` – Amazon S3 AccessDenied detection
* :mod:`bypass.tomcat` – Apache Tomcat IP-restriction detection

Site-specific modules (individual modules in ``sites/``):

* :mod:`sites.base` – Abstract base class for site modules
* :mod:`sites.hp_support` – HP Support (support.hp.com) driver/software downloader

Other modules:

* **extraction** – cloud-storage link, CSS url(), JS path, JSON path extraction
* **storage** – on-disk file writing, content-hash dedup, Git integration
* **downloader** – Page & file downloader with GitHub upload
* **settings** – Configuration constants & WAF signatures
* **url_utils** – URL normalisation & deduplication
* **log_utils** – Logging with ANSI colours & GitHub Actions support
"""

from .detection import detect_all  # noqa: F401
from .extraction import extract_all  # noqa: F401
from .downloader import SiteDownloader  # noqa: F401
from .bypass import (  # noqa: F401
    build_session,
    build_cf_session,
    random_headers,
    cache_bust_url,
    solve_sg_pow,
    solve_sg_captcha,
    is_sg_captcha_response,
    is_s3_access_denied,
    is_tomcat_ip_restricted,
    is_cf_managed_challenge,
    inject_cf_clearance,
    solve_cf_challenge,
)
from .crawler import Crawler  # noqa: F401

__all__ = [
    # detection
    "detect_all",
    # extraction
    "extract_all",
    # downloader
    "SiteDownloader",
    # bypass / session
    "build_session",
    "build_cf_session",
    "random_headers",
    "cache_bust_url",
    "solve_sg_pow",
    "solve_sg_captcha",
    "is_sg_captcha_response",
    "is_s3_access_denied",
    "is_tomcat_ip_restricted",
    "is_cf_managed_challenge",
    "inject_cf_clearance",
    "solve_cf_challenge",
    # crawler
    "Crawler",
]
