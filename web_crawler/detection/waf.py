"""Generic WAF / CAPTCHA signature detection.

Delegates to :mod:`crawl4ai.extensions.detection.waf`.
"""

from crawl4ai.extensions.detection.waf import WAFDetector  # noqa: F401
from crawl4ai.extensions.settings import WAF_SIGNATURES  # noqa: F401

__all__ = ["WAFDetector", "WAF_SIGNATURES"]
