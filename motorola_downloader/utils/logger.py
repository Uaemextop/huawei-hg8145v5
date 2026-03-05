"""Centralized logging module for Motorola Firmware Downloader.

Provides a singleton-based logger factory with:
- Console handler with colored output (optional colorama support)
- Rotating file handler with configurable size and backup count
- Automatic logs/ directory creation
- Configurable log levels from config.ini
- Credential masking to prevent token/password leakage
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

try:
    import colorama
    colorama.init(autoreset=True)
    _COLORAMA_AVAILABLE = True
except ImportError:
    _COLORAMA_AVAILABLE = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_LOG_FILE = "logs/motorola_downloader.log"
DEFAULT_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
DEFAULT_BACKUP_COUNT = 5
LOG_FORMAT = "%(asctime)s [%(name)s] [%(levelname)s] %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Singleton registry for loggers
_loggers: dict[str, logging.Logger] = {}
_initialized: bool = False


# ---------------------------------------------------------------------------
# Color formatter
# ---------------------------------------------------------------------------

class _ColorFormatter(logging.Formatter):
    """Formatter that adds ANSI color codes based on log level."""

    _LEVEL_COLORS: dict[int, str] = {
        logging.DEBUG: "\033[36m",     # Cyan
        logging.INFO: "\033[32m",      # Green
        logging.WARNING: "\033[33m",   # Yellow
        logging.ERROR: "\033[31m",     # Red
        logging.CRITICAL: "\033[1;31m",  # Bold Red
    }
    _RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with ANSI color codes.

        Args:
            record: The log record to format.

        Returns:
            Formatted log string with color codes.
        """
        color = self._LEVEL_COLORS.get(record.levelno, "")
        formatted = super().format(record)
        if color:
            return f"{color}{formatted}{self._RESET}"
        return formatted


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def setup_logging(
    level: str = DEFAULT_LOG_LEVEL,
    log_file: Optional[str] = DEFAULT_LOG_FILE,
    max_bytes: int = DEFAULT_MAX_BYTES,
    backup_count: int = DEFAULT_BACKUP_COUNT,
) -> None:
    """Initialize the logging system for the application.

    Sets up console and optional file handlers on the root 'motorola_downloader'
    logger. Subsequent calls to get_logger() will inherit this configuration.

    Args:
        level: Logging level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Path to the log file. None disables file logging.
        max_bytes: Maximum log file size in bytes before rotation.
        backup_count: Number of rotated log files to keep.
    """
    global _initialized

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root_logger = logging.getLogger("motorola_downloader")
    root_logger.setLevel(numeric_level)
    root_logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(
        _ColorFormatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    )
    root_logger.addHandler(console_handler)

    # File handler (rotating)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            str(log_path),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
        )
        root_logger.addHandler(file_handler)

    _initialized = True


def get_logger(name: str) -> logging.Logger:
    """Get or create a named logger under the motorola_downloader hierarchy.

    Uses a singleton pattern to return the same logger instance for each
    unique name. All loggers are children of the 'motorola_downloader'
    root logger.

    Args:
        name: Logger name, typically __name__ of the calling module.

    Returns:
        A configured logging.Logger instance.
    """
    full_name = f"motorola_downloader.{name}" if not name.startswith("motorola_downloader") else name

    if full_name not in _loggers:
        if not _initialized:
            setup_logging()
        _loggers[full_name] = logging.getLogger(full_name)

    return _loggers[full_name]


def mask_sensitive(value: str, visible_chars: int = 4) -> str:
    """Mask a sensitive value for safe logging.

    Replaces most of the string with asterisks, leaving only the last
    few characters visible for identification purposes.

    Args:
        value: The sensitive string to mask.
        visible_chars: Number of trailing characters to leave visible.

    Returns:
        Masked string like '****abcd'.
    """
    if not value or len(value) <= visible_chars:
        return "****"
    return "*" * (len(value) - visible_chars) + value[-visible_chars:]
