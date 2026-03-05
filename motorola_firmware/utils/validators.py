"""
Input validation utilities for the Motorola Firmware Downloader.

All validators return ``bool`` and log failures through the module logger.
"""

import os
import re
from typing import Optional, Tuple
from urllib.parse import urlparse

from motorola_firmware.utils.logger import log

# ── Validation patterns ────────────────────────────────────────────
_GUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_JWT_PATTERN = re.compile(
    r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"
)

CONTENT_TYPES: Tuple[str, ...] = ("firmware", "rom", "tools", "all")


def validate_guid(guid: str) -> bool:
    """Validate that a string is a properly formatted GUID/UUID.

    Args:
        guid: The string to validate.

    Returns:
        True if the string matches UUID format.
    """
    if not guid or not isinstance(guid, str):
        log.warning("[WARN] GUID validation failed: empty or non-string input")
        return False
    if not _GUID_PATTERN.match(guid.strip()):
        log.warning("[WARN] GUID validation failed: invalid format")
        return False
    return True


def validate_jwt(token: str) -> bool:
    """Validate that a string has valid JWT format (three base64url segments).

    Args:
        token: The string to validate.

    Returns:
        True if the string has valid JWT structure.
    """
    if not token or not isinstance(token, str):
        log.warning("[WARN] JWT validation failed: empty or non-string input")
        return False
    if not _JWT_PATTERN.match(token.strip()):
        log.warning("[WARN] JWT validation failed: invalid format")
        return False
    return True


def validate_url(url: str, require_https: bool = True) -> bool:
    """Validate that a string is a properly formatted URL.

    Args:
        url: The string to validate.
        require_https: If True, only HTTPS URLs are considered valid.

    Returns:
        True if the string is a valid URL.
    """
    if not url or not isinstance(url, str):
        log.warning("[WARN] URL validation failed: empty or non-string input")
        return False
    try:
        parsed = urlparse(url.strip())
        if not parsed.scheme or not parsed.netloc:
            log.warning("[WARN] URL validation failed: missing scheme or host")
            return False
        if require_https and parsed.scheme != "https":
            log.warning("[WARN] URL validation failed: HTTPS required")
            return False
        if parsed.scheme not in ("http", "https"):
            log.warning("[WARN] URL validation failed: invalid scheme")
            return False
        return True
    except ValueError:
        log.warning("[WARN] URL validation failed: malformed URL")
        return False


def validate_file_path(path: str, must_exist: bool = False) -> bool:
    """Validate that a file path is safe (no path traversal).

    Args:
        path: The file path to validate.
        must_exist: If True, the path must exist on disk.

    Returns:
        True if the path is valid and safe.
    """
    if not path or not isinstance(path, str):
        log.warning("[WARN] Path validation failed: empty or non-string input")
        return False
    normalized = os.path.normpath(path)
    if ".." in normalized.split(os.sep):
        log.warning("[WARN] Path validation failed: path traversal detected")
        return False
    if must_exist and not os.path.exists(normalized):
        log.warning("[WARN] Path validation failed: path does not exist")
        return False
    return True


def validate_search_query(query: str, max_length: int = 200) -> bool:
    """Validate a search query string.

    Args:
        query: The search query to validate.
        max_length: Maximum allowed query length.

    Returns:
        True if the query is valid.
    """
    if not query or not isinstance(query, str):
        log.warning("[WARN] Search query validation failed: empty or non-string")
        return False
    stripped = query.strip()
    if len(stripped) == 0:
        log.warning("[WARN] Search query validation failed: empty after strip")
        return False
    if len(stripped) > max_length:
        log.warning("[WARN] Search query validation failed: exceeds max length")
        return False
    return True


def validate_content_type(content_type: str) -> bool:
    """Validate a content type filter value.

    Args:
        content_type: The content type to validate (firmware, rom, tools, all).

    Returns:
        True if the content type is valid.
    """
    if not content_type or not isinstance(content_type, str):
        log.warning("[WARN] Content type validation failed: empty or non-string")
        return False
    if content_type.lower().strip() not in CONTENT_TYPES:
        log.warning("[WARN] Content type validation failed: '%s' not allowed", content_type)
        return False
    return True
