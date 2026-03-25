"""HTTP session creation, bypass helpers, and CAPTCHA solvers.

Delegates to :mod:`crawl4ai.extensions.bypass` submodules — the canonical
implementation shared by both ``web_crawler`` and ``crawl4ai``.

All public functions previously defined here are now re-exported from their
respective ``crawl4ai.extensions.bypass.*`` modules.
"""

from crawl4ai.extensions.bypass.session import (  # noqa: F401
    build_session,
    random_headers,
    cache_bust_url,
    _client_hints_for_ua,
)
from crawl4ai.extensions.bypass.cloudflare import (  # noqa: F401
    build_cf_session,
    is_cf_managed_challenge,
    inject_cf_clearance,
    solve_cf_challenge,
)
from crawl4ai.extensions.bypass.siteground import (  # noqa: F401
    solve_sg_pow,
    solve_sg_captcha,
    is_sg_captcha_response,
)
from crawl4ai.extensions.bypass.s3 import is_s3_access_denied  # noqa: F401
from crawl4ai.extensions.bypass.tomcat import is_tomcat_ip_restricted  # noqa: F401

__all__ = [
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
]
