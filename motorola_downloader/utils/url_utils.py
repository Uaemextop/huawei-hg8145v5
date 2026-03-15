"""URL normalization and handling utilities for Motorola Firmware Downloader.

Provides URL processing functions for firmware download URLs, including
scheme normalization, S3 host detection, and download filename extraction.
Patterns from web_crawler/auth/lmsa.py collect_download_urls() and
web_crawler/utils/url.py normalise_url().
"""

import os
import re
from typing import Optional, Tuple
from urllib.parse import urlparse, urljoin, quote

from motorola_downloader.utils.logger import get_logger

_logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Host classifications (from LMSA analysis)
# ---------------------------------------------------------------------------

#: S3 hosts that require AWS pre-signed URLs for access.
S3_PRIVATE_HOSTS = frozenset({
    "rsddownload-secure.lenovo.com",
    "moto-rsd-prod-secure.s3.us-east-1.amazonaws.com",
})

#: Public hosts where firmware can be downloaded without authentication.
PUBLIC_HOSTS = frozenset({
    "download.lenovo.com",
})

#: Internal hosts that are not accessible from the public internet.
INTERNAL_HOSTS = frozenset({
    "rsdsecure-cloud.motorola.com",
})

#: Firmware file extensions recognized by the download system.
FIRMWARE_EXTENSIONS = frozenset({
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".bin", ".exe", ".img", ".iso",
    ".hwnp", ".fwu", ".pkg",
    ".xml", ".json",
})


def normalize_url(url: str) -> str:
    """Normalize a URL to ensure it has a valid HTTPS scheme.

    Handles protocol-relative URLs (//), scheme-less URLs, and
    JSON-escaped forward slashes (\\/).
    Matches the normalization patterns from lmsa.py collect_download_urls().

    Args:
        url: Raw URL string to normalize.

    Returns:
        Normalized URL with https:// scheme, or empty string if invalid.
    """
    if not url or not isinstance(url, str):
        return ""

    # Fix JSON-escaped slashes (from web_crawler/utils/url.py)
    url = url.replace("\\/", "/")

    url = url.strip()

    # Protocol-relative URLs
    if url.startswith("//"):
        url = "https:" + url
    # Scheme-less URLs (but not local paths)
    elif not url.startswith(("http://", "https://")):
        if "/" in url and "." in url.split("/")[0]:
            url = "https://" + url
        else:
            return ""

    return url


def extract_filename(url: str, default_name: str = "firmware.zip") -> str:
    """Extract the filename from a download URL.

    Strips query parameters and URL fragments to get the clean filename
    from the URL path. Matches the pattern from lmsa.py collect_download_urls()::

        name = base.rstrip("/").rsplit("/", 1)[-1] or default_name

    Args:
        url: Download URL.
        default_name: Fallback filename if extraction fails.

    Returns:
        Extracted filename string.
    """
    if not url:
        return default_name

    try:
        # Strip query string and fragment
        base = url.split("?")[0].split("#")[0]
        # Extract filename from path
        name = base.rstrip("/").rsplit("/", 1)[-1]
        return name if name else default_name
    except (ValueError, IndexError):
        return default_name


def get_base_url(url: str) -> str:
    """Get the base URL without query string (for deduplication).

    Used for deduplication of S3 pre-signed URLs that differ only in
    their signing parameters. Matches the dedup pattern from lmsa.py
    collect_download_urls()::

        base = url_val.split("?")[0]

    Args:
        url: Full URL possibly with query parameters.

    Returns:
        URL string without query parameters.
    """
    if not url:
        return ""
    return url.split("?")[0]


def is_s3_host(host: str) -> bool:
    """Check if a host is an S3 private bucket.

    Args:
        host: Hostname string to check.

    Returns:
        True if the host is a known S3 private bucket.
    """
    if not host:
        return False
    return host.lower() in S3_PRIVATE_HOSTS


def is_public_host(host: str) -> bool:
    """Check if a host serves firmware publicly (no auth needed).

    Args:
        host: Hostname string to check.

    Returns:
        True if the host serves files without authentication.
    """
    if not host:
        return False
    return host.lower() in PUBLIC_HOSTS


def is_internal_host(host: str) -> bool:
    """Check if a host is internal (not publicly accessible).

    Args:
        host: Hostname string to check.

    Returns:
        True if the host is internal/unreachable.
    """
    if not host:
        return False
    return host.lower() in INTERNAL_HOSTS


def get_host(url: str) -> str:
    """Extract the hostname from a URL.

    Args:
        url: URL string.

    Returns:
        Hostname string, or empty string if extraction fails.
    """
    try:
        return urlparse(url).netloc.lower()
    except (ValueError, AttributeError):
        return ""


def classify_download_url(url: str) -> str:
    """Classify a download URL by its hosting type.

    Returns one of: 'public', 's3_private', 'internal', 'unknown'.

    Args:
        url: Download URL to classify.

    Returns:
        Classification string.
    """
    host = get_host(url)
    if not host:
        return "unknown"
    if is_public_host(host):
        return "public"
    if is_s3_host(host):
        return "s3_private"
    if is_internal_host(host):
        return "internal"
    return "unknown"


def is_firmware_url(url: str) -> bool:
    """Check if a URL points to a firmware file based on extension.

    Args:
        url: URL string to check.

    Returns:
        True if the URL path ends with a known firmware extension.
    """
    if not url:
        return False

    try:
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in FIRMWARE_EXTENSIONS)
    except (ValueError, AttributeError):
        return False


def build_api_url(base_url: str, endpoint: str) -> str:
    """Build a full API URL from base URL and endpoint path.

    Args:
        base_url: LMSA API base URL (e.g. 'https://lsa.lenovo.com/Interface').
        endpoint: API endpoint path (e.g. '/rescueDevice/getNewResource.jhtml').

    Returns:
        Complete API URL string.
    """
    base = base_url.rstrip("/")
    path = endpoint if endpoint.startswith("/") else f"/{endpoint}"
    return f"{base}{path}"


def deduplicate_urls(
    url_pairs: list[Tuple[str, str]],
) -> list[Tuple[str, str]]:
    """Deduplicate URL pairs by base URL (without query string).

    Matches the dedup logic from lmsa.py collect_download_urls() where
    different pre-signed tokens for the same file are deduplicated.

    Args:
        url_pairs: List of (url, filename) tuples.

    Returns:
        Deduplicated list of (url, filename) tuples.
    """
    seen: set[str] = set()
    unique: list[Tuple[str, str]] = []

    for url, name in url_pairs:
        base = get_base_url(url)
        if base and base not in seen:
            seen.add(base)
            unique.append((url, name))

    removed = len(url_pairs) - len(unique)
    if removed > 0:
        _logger.info("Deduplicated %d URLs (removed %d duplicates)", len(unique), removed)

    return unique
