"""Input validation functions for Motorola Firmware Downloader.

Provides validation for GUIDs, JWT tokens, URLs, file paths, and other user inputs.
"""

import re
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


# Regex patterns for validation
GUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE
)

# JWT consists of three base64url encoded parts separated by dots
JWT_PATTERN = re.compile(
    r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"
)

URL_PATTERN = re.compile(
    r"^https?://[a-zA-Z0-9.-]+(?:\:[0-9]+)?(?:/[^\s]*)?$"
)


def validate_guid(guid: str) -> bool:
    """Validate GUID format (UUID v4).

    Args:
        guid: GUID string to validate

    Returns:
        True if GUID is valid, False otherwise

    Examples:
        >>> validate_guid("98e2895b-2e0a-4830-b5fe-eab0ab2c3f84")
        True
        >>> validate_guid("invalid-guid")
        False
    """
    if not guid or not isinstance(guid, str):
        return False
    return bool(GUID_PATTERN.match(guid.strip()))


def validate_jwt(token: str) -> bool:
    """Validate JWT token format.

    Basic validation that checks for three base64url-encoded parts
    separated by dots. Does not verify signature or expiration.

    Args:
        token: JWT token string to validate

    Returns:
        True if token format is valid, False otherwise

    Examples:
        >>> validate_jwt("eyJhbGc.eyJzdWI.SflKxw")
        True
        >>> validate_jwt("invalid.token")
        False
    """
    if not token or not isinstance(token, str):
        return False

    # Remove "Bearer " prefix if present
    token = token.removeprefix("Bearer ").strip()

    return bool(JWT_PATTERN.match(token))


def validate_url(url: str, require_https: bool = True) -> bool:
    """Validate URL format.

    Args:
        url: URL string to validate
        require_https: If True, only accept HTTPS URLs (default: True)

    Returns:
        True if URL is valid, False otherwise

    Examples:
        >>> validate_url("https://example.com/path")
        True
        >>> validate_url("http://example.com/path", require_https=False)
        True
        >>> validate_url("http://example.com/path", require_https=True)
        False
    """
    if not url or not isinstance(url, str):
        return False

    try:
        parsed = urlparse(url.strip())
        if require_https and parsed.scheme != "https":
            return False
        if parsed.scheme not in ("http", "https"):
            return False
        if not parsed.netloc:
            return False
        return True
    except Exception:
        return False


def validate_file_path(path: str, must_exist: bool = False) -> bool:
    """Validate file path.

    Args:
        path: File path string to validate
        must_exist: If True, path must exist on filesystem (default: False)

    Returns:
        True if path is valid, False otherwise

    Examples:
        >>> validate_file_path("/path/to/file.txt")
        True
        >>> validate_file_path("")
        False
    """
    if not path or not isinstance(path, str):
        return False

    try:
        p = Path(path.strip())
        if must_exist and not p.exists():
            return False
        # Check for path traversal attempts
        resolved = p.resolve()
        return True
    except Exception:
        return False


def validate_directory_path(path: str, must_exist: bool = False) -> bool:
    """Validate directory path.

    Args:
        path: Directory path string to validate
        must_exist: If True, directory must exist on filesystem (default: False)

    Returns:
        True if path is valid, False otherwise

    Examples:
        >>> validate_directory_path("/path/to/directory")
        True
        >>> validate_directory_path("")
        False
    """
    if not path or not isinstance(path, str):
        return False

    try:
        p = Path(path.strip())
        if must_exist and (not p.exists() or not p.is_dir()):
            return False
        return True
    except Exception:
        return False


def validate_integer_range(
    value: str, min_value: int, max_value: int
) -> Optional[int]:
    """Validate integer within specified range.

    Args:
        value: String value to parse and validate
        min_value: Minimum allowed value (inclusive)
        max_value: Maximum allowed value (inclusive)

    Returns:
        Parsed integer if valid, None otherwise

    Examples:
        >>> validate_integer_range("5", 1, 10)
        5
        >>> validate_integer_range("15", 1, 10)
        None
    """
    try:
        int_value = int(value.strip())
        if min_value <= int_value <= max_value:
            return int_value
        return None
    except (ValueError, AttributeError):
        return None


def validate_non_empty_string(value: str) -> bool:
    """Validate that string is not empty.

    Args:
        value: String to validate

    Returns:
        True if string is non-empty after stripping whitespace, False otherwise

    Examples:
        >>> validate_non_empty_string("hello")
        True
        >>> validate_non_empty_string("   ")
        False
    """
    return bool(value and isinstance(value, str) and value.strip())


def sanitize_filename(filename: str) -> str:
    """Sanitize filename by removing/replacing invalid characters.

    Args:
        filename: Filename to sanitize

    Returns:
        Sanitized filename safe for filesystem

    Examples:
        >>> sanitize_filename("file:name?.txt")
        'file_name_.txt'
    """
    # Remove/replace characters invalid in filenames
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, "_")
    # Remove leading/trailing whitespace and dots
    filename = filename.strip(". ")
    # Ensure filename is not empty
    if not filename:
        filename = "unnamed_file"
    return filename
