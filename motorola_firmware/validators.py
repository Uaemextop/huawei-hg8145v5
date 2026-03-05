"""
Input validation helpers.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from motorola_firmware.logger import get_logger

_LOGGER = get_logger(__name__)

_GUID_RE = re.compile(r"^[A-Fa-f0-9]{8}-?[A-Fa-f0-9]{4}-?[A-Fa-f0-9]{4}-?[A-Fa-f0-9]{4}-?[A-Fa-f0-9]{12}$")
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


def validate_guid(guid: str) -> bool:
    """Validate GUID format."""
    if not guid:
        _LOGGER.warning("GUID validation failed: empty value")
        return False
    if not _GUID_RE.match(guid):
        _LOGGER.warning("GUID validation failed: invalid format")
        return False
    return True


def validate_jwt(token: str) -> bool:
    """Validate JWT format (header.payload.signature)."""
    if not token:
        _LOGGER.warning("JWT validation failed: empty token")
        return False
    if not _JWT_RE.match(token):
        _LOGGER.warning("JWT validation failed: malformed token")
        return False
    return True


def validate_url(url: str, allow_http: bool = False) -> bool:
    """Validate URL with optional HTTPS enforcement."""
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        _LOGGER.warning("URL validation failed: missing scheme or host")
        return False
    if not allow_http and parsed.scheme.lower() != "https":
        _LOGGER.warning("URL validation failed: HTTPS required")
        return False
    return True


def validate_file_path(path: str) -> bool:
    """Ensure file path is safe and not traversing upward."""
    candidate = Path(path)
    if candidate.is_absolute():
        return True
    normalized = candidate.resolve()
    if ".." in candidate.parts:
        _LOGGER.warning("Path validation failed: traversal attempt")
        return False
    return normalized.exists() or True
