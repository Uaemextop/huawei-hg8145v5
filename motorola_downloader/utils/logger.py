"""Centralized logging module for Motorola Firmware Downloader.

Provides a singleton-based logger factory with:
- Debug mode: verbose output with timestamps, module names, and all levels
- Normal mode: clean, minimalist INFO-only output for end users
- Console handler with colorama-powered colored output
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
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
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

# Verbose format for debug mode (timestamps + module + level)
DEBUG_LOG_FORMAT = "%(asctime)s [%(name)s] [%(levelname)s] %(message)s"
# Minimal format for normal mode (clean user-facing output)
MINIMAL_LOG_FORMAT = "%(levelname)s: %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
FILE_LOG_FORMAT = "%(asctime)s [%(name)s] [%(levelname)s] %(message)s"

# Singleton registry for loggers
_loggers: dict[str, logging.Logger] = {}
_initialized: bool = False
_debug_mode: bool = False


# ---------------------------------------------------------------------------
# Color formatter using colorama
# ---------------------------------------------------------------------------

class _ColorFormatter(logging.Formatter):
    """Formatter that adds colorama colors based on log level.

    Uses colorama for cross-platform colored terminal output.
    In debug mode, uses verbose format with timestamps and module names.
    In normal mode, uses minimal clean format for end users.
    """

    def __init__(self, fmt: str, datefmt: Optional[str] = None, debug: bool = False) -> None:
        """Initialize the color formatter.

        Args:
            fmt: Log format string.
            datefmt: Date format string.
            debug: Whether debug mode is active.
        """
        super().__init__(fmt, datefmt=datefmt)
        self._debug = debug

        if _COLORAMA_AVAILABLE:
            self._level_colors: dict[int, str] = {
                logging.DEBUG: Fore.CYAN,
                logging.INFO: Fore.GREEN,
                logging.WARNING: Fore.YELLOW,
                logging.ERROR: Fore.RED,
                logging.CRITICAL: Fore.RED + Style.BRIGHT,
            }
            self._reset = Style.RESET_ALL
        else:
            self._level_colors = {
                logging.DEBUG: "\033[36m",
                logging.INFO: "\033[32m",
                logging.WARNING: "\033[33m",
                logging.ERROR: "\033[31m",
                logging.CRITICAL: "\033[1;31m",
            }
            self._reset = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colorama colors.

        Args:
            record: The log record to format.

        Returns:
            Formatted log string with color codes.
        """
        color = self._level_colors.get(record.levelno, "")
        formatted = super().format(record)
        if color:
            return f"{color}{formatted}{self._reset}"
        return formatted


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def setup_logging(
    level: str = DEFAULT_LOG_LEVEL,
    log_file: Optional[str] = DEFAULT_LOG_FILE,
    max_bytes: int = DEFAULT_MAX_BYTES,
    backup_count: int = DEFAULT_BACKUP_COUNT,
    debug: bool = False,
) -> None:
    """Initialize the logging system for the application.

    Sets up console and optional file handlers on the root 'motorola_downloader'
    logger. When debug=True, console shows all levels with verbose timestamps
    and module names. When debug=False, console shows only INFO+ with clean
    minimal format.

    Args:
        level: Logging level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Path to the log file. None disables file logging.
        max_bytes: Maximum log file size in bytes before rotation.
        backup_count: Number of rotated log files to keep.
        debug: Enable debug mode for verbose console output.
    """
    global _initialized, _debug_mode

    _debug_mode = debug

    if debug:
        numeric_level = logging.DEBUG
        console_format = DEBUG_LOG_FORMAT
    else:
        numeric_level = getattr(logging, level.upper(), logging.INFO)
        console_format = MINIMAL_LOG_FORMAT

    root_logger = logging.getLogger("motorola_downloader")
    root_logger.setLevel(logging.DEBUG)  # Always capture all to file
    root_logger.handlers.clear()

    # Console handler — level depends on debug mode
    console_handler = logging.StreamHandler()
    console_level = logging.DEBUG if debug else max(numeric_level, logging.INFO)
    console_handler.setLevel(console_level)
    console_handler.setFormatter(
        _ColorFormatter(
            console_format,
            datefmt=LOG_DATE_FORMAT if debug else None,
            debug=debug,
        )
    )
    root_logger.addHandler(console_handler)

    # File handler (rotating) — always captures DEBUG for diagnostics
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
            logging.Formatter(FILE_LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
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


def is_debug_mode() -> bool:
    """Check whether debug mode is currently active.

    Returns:
        True if debug mode is enabled, False otherwise.
    """
    return _debug_mode


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
