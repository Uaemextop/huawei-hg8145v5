"""
Global constants and configuration for the Motorola Firmware Downloader.

Modelled after ``web_crawler.config`` — all tunable parameters and API
endpoints live here so they can be imported by any module.
"""

import os
from typing import Tuple

# ── Network defaults ───────────────────────────────────────────────
REQUEST_TIMEOUT = 30          # seconds
MAX_RETRIES = 3
BACKOFF_BASE = 1.0            # exponential backoff base delay (1s, 2s, 4s)
DEFAULT_CHUNK_SIZE = 8192     # bytes per download chunk

# ── Concurrency ────────────────────────────────────────────────────
DEFAULT_CONCURRENT_DOWNLOADS = 3
MIN_CONCURRENT_DOWNLOADS = 1
MAX_CONCURRENT_DOWNLOADS = 5

# ── Motorola API ───────────────────────────────────────────────────
#: Base URL for the Motorola firmware API.  Update this in config.ini
#: with the actual server address obtained from device traffic capture.
MOTOROLA_BASE_URL = "https://motorola-firmware.example.com/api"

#: API endpoint paths
EP_AUTH_LOGIN    = "/auth/login"
EP_AUTH_REFRESH  = "/auth/refresh"
EP_FIRMWARE_SEARCH   = "/firmware/search"
EP_FIRMWARE_SUGGEST  = "/firmware/suggest"
EP_FIRMWARE_DOWNLOAD = "/firmware/download"

#: LMSA-style headers (from web_crawler.auth.lmsa reference)
CLIENT_VERSION = "1.0.0"

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

#: User-Agent pool for rotation (modelled after web_crawler.config)
USER_AGENTS: Tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
)

#: Known Motorola device regions (based on web_crawler LMSA countries)
FIRMWARE_REGIONS: Tuple[str, ...] = (
    "Mexico", "US", "Brazil", "Argentina", "Colombia", "Chile",
    "Peru", "Ecuador", "Guatemala", "Paraguay", "Dominican Republic",
    "India", "Germany", "UK", "France", "Italy", "Spain", "Australia",
    "Canada", "Japan", "China", "global",
)

#: Content types for firmware search
CONTENT_TYPE_FIRMWARE = "firmware"
CONTENT_TYPE_ROM = "rom"
CONTENT_TYPE_TOOLS = "tools"
CONTENT_TYPE_ALL = "all"
VALID_CONTENT_TYPES = (
    CONTENT_TYPE_FIRMWARE, CONTENT_TYPE_ROM,
    CONTENT_TYPE_TOOLS, CONTENT_TYPE_ALL,
)

# ── Authentication ─────────────────────────────────────────────────
TOKEN_EXPIRY_MARGIN = 300     # seconds before expiry to trigger refresh
MAX_AUTH_RETRIES = 3

# ── Search ─────────────────────────────────────────────────────────
DEFAULT_SEARCH_LIMIT = 20
MAX_CACHE_SIZE = 50

# ── Download ───────────────────────────────────────────────────────
RETRY_BASE_DELAY = 2.0       # seconds
MAX_DOWNLOAD_RETRIES = 3

# ── Paths ──────────────────────────────────────────────────────────
DEFAULT_OUTPUT_DIR = "downloads"
DEFAULT_CONFIG_FILE = "config.ini"
DEFAULT_LOG_DIR = "logs"
DEFAULT_LOG_FILE = "motorola_firmware.log"


def auto_concurrency() -> int:
    """Determine optimal concurrency from CPU count.

    Returns:
        Number of concurrent workers (clamped between 1 and 5).
    """
    cpu = os.cpu_count() or 2
    workers = min(cpu, MAX_CONCURRENT_DOWNLOADS)
    return max(MIN_CONCURRENT_DOWNLOADS, workers)
