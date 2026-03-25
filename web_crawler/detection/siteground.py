"""SiteGround Security CAPTCHA detection.

Delegates to :mod:`crawl4ai.extensions.detection.siteground`.
"""

from crawl4ai.extensions.detection.siteground import SiteGroundDetector  # noqa: F401

__all__ = ["SiteGroundDetector"]
