"""
Anti-blocking layer for the web crawler.

Provides rate limiting, user-agent rotation, retry management,
and block detection to avoid being blocked by target sites.
"""

from web_crawler.anti_blocking.rate_limiter import RateLimiter
from web_crawler.anti_blocking.block_detector import BlockDetector

__all__ = ["RateLimiter", "BlockDetector"]
