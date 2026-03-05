"""Input validation utilities for Motorola Firmware Downloader.

Provides validation functions for GUIDs, JWT tokens, URLs, file paths,
and other user inputs. All validators return bool and log failures.
"""

import os
import re
from typing import Optional
from urllib.parse import urlparse

from motorola_downloader.utils.logger import get_logger

_logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# UUID v4 format: 8-4-4-4-12 hex characters
_GUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# JWT format: three Base64url-encoded segments separated by dots
_JWT_PATTERN = re.compile(
    r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"
)

# Allowed URL schemes
_ALLOWED_SCHEMES = {"https"}

# Dangerous path patterns for path traversal prevention
_PATH_TRAVERSAL_PATTERN = re.compile(r"\.\.")


# ---------------------------------------------------------------------------
# Validation functions
# ---------------------------------------------------------------------------

def validate_guid(guid: str) -> bool:
    """Validate that a GUID string is in proper UUID v4 format.

    Args:
        guid: The GUID string to validate.

    Returns:
        True if the GUID is valid, False otherwise.
    """
    if not guid or not isinstance(guid, str):
        _logger.warning("GUID validation failed: empty or non-string value")
        return False

    if not _GUID_PATTERN.match(guid.strip()):
        _logger.warning("GUID validation failed: invalid format")
        return False

    return True


def validate_jwt(token: str) -> bool:
    """Validate that a JWT token has the correct three-part structure.

    This performs format validation only; it does not verify the signature
    or check expiration.

    Args:
        token: The JWT token string to validate.

    Returns:
        True if the token format is valid, False otherwise.
    """
    if not token or not isinstance(token, str):
        _logger.warning("JWT validation failed: empty or non-string value")
        return False

    clean_token = token.strip()
    if clean_token.startswith("Bearer "):
        clean_token = clean_token[7:]

    if not _JWT_PATTERN.match(clean_token):
        _logger.warning("JWT validation failed: invalid three-part structure")
        return False

    return True


def validate_url(url: str) -> bool:
    """Validate that a URL is well-formed and uses HTTPS.

    Args:
        url: The URL string to validate.

    Returns:
        True if the URL is valid and uses HTTPS, False otherwise.
    """
    if not url or not isinstance(url, str):
        _logger.warning("URL validation failed: empty or non-string value")
        return False

    try:
        parsed = urlparse(url.strip())
    except ValueError:
        _logger.warning("URL validation failed: malformed URL")
        return False

    if parsed.scheme not in _ALLOWED_SCHEMES:
        _logger.warning(
            "URL validation failed: scheme '%s' not allowed (HTTPS required)",
            parsed.scheme,
        )
        return False

    if not parsed.netloc:
        _logger.warning("URL validation failed: missing hostname")
        return False

    return True


def validate_file_path(path: str) -> bool:
    """Validate that a file path is safe and does not contain traversal patterns.

    Args:
        path: The file path string to validate.

    Returns:
        True if the path is safe, False otherwise.
    """
    if not path or not isinstance(path, str):
        _logger.warning("File path validation failed: empty or non-string value")
        return False

    normalized = os.path.normpath(path.strip())

    if _PATH_TRAVERSAL_PATTERN.search(normalized):
        _logger.warning("File path validation failed: path traversal detected")
        return False

    return True


def validate_positive_int(value: str, min_val: int = 1, max_val: int = 100) -> bool:
    """Validate that a string represents a positive integer within a range.

    Args:
        value: The string value to validate.
        min_val: Minimum allowed value (inclusive).
        max_val: Maximum allowed value (inclusive).

    Returns:
        True if valid, False otherwise.
    """
    if not value or not isinstance(value, str):
        _logger.warning("Integer validation failed: empty or non-string value")
        return False

    try:
        num = int(value.strip())
    except ValueError:
        _logger.warning("Integer validation failed: '%s' is not a number", value)
        return False

    if num < min_val or num > max_val:
        _logger.warning(
            "Integer validation failed: %d not in range [%d, %d]",
            num, min_val, max_val,
        )
        return False

    return True


def validate_search_query(query: str) -> bool:
    """Validate a search query string.

    Args:
        query: The search query to validate.

    Returns:
        True if the query is valid, False otherwise.
    """
    if not query or not isinstance(query, str):
        _logger.warning("Search query validation failed: empty or non-string value")
        return False

    cleaned = query.strip()
    if len(cleaned) < 2:
        _logger.warning("Search query validation failed: query too short (min 2 chars)")
        return False

    if len(cleaned) > 200:
        _logger.warning("Search query validation failed: query too long (max 200 chars)")
        return False

    return True


def validate_content_type(content_type: str) -> bool:
    """Validate that a content type is one of the allowed values.

    Args:
        content_type: Content type to validate (Firmware, ROM, Tools, All).

    Returns:
        True if valid, False otherwise.
    """
    allowed = {"firmware", "rom", "tools", "all"}
    if not content_type or not isinstance(content_type, str):
        _logger.warning("Content type validation failed: empty or non-string value")
        return False

    if content_type.strip().lower() not in allowed:
        _logger.warning(
            "Content type validation failed: '%s' not in %s",
            content_type, allowed,
        )
        return False

    return True
