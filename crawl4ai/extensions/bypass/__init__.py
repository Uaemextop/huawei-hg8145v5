"""
crawl4ai.extensions.bypass – WAF / CAPTCHA bypass & correction modules.

Individual modules:

* :mod:`.session` – HTTP session builder (retry, UA rotation, Client Hints, cache-busting)
* :mod:`.cloudflare` – Cloudflare Managed Challenge bypass (curl_cffi + Playwright)
* :mod:`.siteground` – SiteGround PoW CAPTCHA solver
* :mod:`.s3` – Amazon S3 private-bucket (AccessDenied) detection
* :mod:`.tomcat` – Apache Tomcat IP-restriction detection
"""

from __future__ import annotations

from .session import (
    build_session,
    random_headers,
    cache_bust_url,
    USER_AGENTS,
    MAX_RETRIES,
)
from .cloudflare import (
    build_cf_session,
    is_cf_managed_challenge,
    inject_cf_clearance,
    solve_cf_challenge,
)
from .siteground import (
    solve_sg_pow,
    solve_sg_captcha,
    is_sg_captcha_response,
)
from .s3 import is_s3_access_denied
from .tomcat import is_tomcat_ip_restricted

__all__ = [
    # session
    "build_session",
    "random_headers",
    "cache_bust_url",
    "USER_AGENTS",
    "MAX_RETRIES",
    # cloudflare
    "build_cf_session",
    "is_cf_managed_challenge",
    "inject_cf_clearance",
    "solve_cf_challenge",
    # siteground
    "solve_sg_pow",
    "solve_sg_captcha",
    "is_sg_captcha_response",
    # s3
    "is_s3_access_denied",
    # tomcat
    "is_tomcat_ip_restricted",
]
