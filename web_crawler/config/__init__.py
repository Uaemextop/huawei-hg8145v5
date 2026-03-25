"""Crawler configuration and constants.

Re-exports from :mod:`crawl4ai.extensions.settings`.
"""

from web_crawler.config.settings import (  # noqa: F401
    DEFAULT_OUTPUT,
    DEFAULT_MAX_DEPTH,
    DEFAULT_DELAY,
    DEFAULT_CONCURRENCY,
    DEFAULT_DOWNLOAD_EXTENSIONS,
    auto_concurrency,
    REQUEST_TIMEOUT,
    MAX_RETRIES,
    HEADER_RETRY_MAX,
    BACKOFF_429_BASE,
    BACKOFF_429_MAX,
    PROBE_403_THRESHOLD,
    PROBE_404_THRESHOLD,
    PROBE_DIR_404_LIMIT,
    MAX_URL_RETRIES,
    STREAM_SIZE_THRESHOLD,
    BINARY_CONTENT_TYPES,
    USER_AGENTS,
)
