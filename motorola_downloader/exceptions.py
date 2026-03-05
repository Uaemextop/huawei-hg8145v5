"""Custom exception classes for Motorola Firmware Downloader."""


class MotorolaDownloaderError(Exception):
    """Base exception for all Motorola Downloader errors."""


class AuthenticationError(MotorolaDownloaderError):
    """Raised when authentication fails.

    This includes invalid credentials, expired tokens,
    and server-side authentication rejections.
    """


class TokenExpiredError(AuthenticationError):
    """Raised when the JWT token has expired and cannot be refreshed."""


class ConfigurationError(MotorolaDownloaderError):
    """Raised when configuration is invalid or missing required fields."""


class DownloadError(MotorolaDownloaderError):
    """Raised when a file download fails after all retry attempts."""


class SearchError(MotorolaDownloaderError):
    """Raised when a search operation fails."""


class ValidationError(MotorolaDownloaderError):
    """Raised when input validation fails."""


class HTTPClientError(MotorolaDownloaderError):
    """Raised when an HTTP request fails."""


class EncryptionError(MotorolaDownloaderError):
    """Raised when encryption or decryption operations fail."""


class SessionError(MotorolaDownloaderError):
    """Raised when session management operations fail."""
