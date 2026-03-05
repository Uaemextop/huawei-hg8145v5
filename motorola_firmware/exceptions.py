"""
Custom exceptions for the Motorola Firmware Downloader.

All domain-specific errors inherit from :class:`MotorolaFirmwareError`
so callers can catch the whole family with a single ``except`` clause.
"""


class MotorolaFirmwareError(Exception):
    """Base exception for the Motorola Firmware Downloader."""


class AuthenticationError(MotorolaFirmwareError):
    """Raised when authentication with the Motorola server fails."""


class ConfigurationError(MotorolaFirmwareError):
    """Raised when configuration is invalid or missing required fields."""


class DownloadError(MotorolaFirmwareError):
    """Raised when a file download fails after all retries."""


class SearchError(MotorolaFirmwareError):
    """Raised when a firmware search operation fails."""


class SessionError(MotorolaFirmwareError):
    """Raised when a session operation fails."""


class HttpClientError(MotorolaFirmwareError):
    """Raised when an HTTP request fails."""
