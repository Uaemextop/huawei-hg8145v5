"""
Logging configuration for the Motorola Firmware Downloader.

Provides a clean logging system with:
* ANSI colour highlights for ``[CATEGORY]`` tags
* Rotating file handler (5 MB, 5 backups)
* Console handler with colour support (if ``colorlog`` is installed)
* Singleton-style module-level logger

Modelled after the web_crawler logging system.
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

try:
    import colorlog
    _COLORLOG_AVAILABLE = True
except ImportError:
    _COLORLOG_AVAILABLE = False

# Module-level logger (singleton-style, shared by all modules)
log = logging.getLogger("motorola-firmware")

# Defaults
DEFAULT_LOG_DIR = "logs"
DEFAULT_LOG_FILE = "motorola_firmware.log"
DEFAULT_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
DEFAULT_BACKUP_COUNT = 5
_FILE_LOG_FMT = "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
_FILE_LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"

# ── Category colours ───────────────────────────────────────────────
_ANSI_RESET = "\033[0m"
_CATEGORY_STYLES: dict[str, str] = {
    "[AUTH]":     "\033[1;33m",
    "[SESSION]":  "\033[1;36m",
    "[SEARCH]":   "\033[1;35m",
    "[DOWNLOAD]": "\033[1;32m",
    "[CONFIG]":   "\033[34m",
    "[HTTP]":     "\033[36m",
    "[ERR]":      "\033[1;31m",
    "[CRYPTO]":   "\033[33m",
    "[CLI]":      "\033[37m",
    "[RETRY]":    "\033[36m",
    "[SAVE]":     "\033[1;32m",
    "[SKIP]":     "\033[90m",
    "[WARN]":     "\033[33m",
}


def _apply_category_styles(msg: str) -> str:
    """Inject ANSI colours for known ``[CATEGORY]`` tags in *msg*."""
    for tag, style in _CATEGORY_STYLES.items():
        if tag in msg:
            msg = msg.replace(tag, f"{style}{tag}{_ANSI_RESET}")
    return msg


class _CategoryFormatter(logging.Formatter):
    """Formatter that highlights known ``[CATEGORY]`` tags with ANSI colours."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with category colour highlighting.

        Args:
            record: The log record to format.

        Returns:
            Formatted string with ANSI colour codes.
        """
        return _apply_category_styles(super().format(record))


class _ColorlogCategoryFormatter(
    colorlog.ColoredFormatter if _COLORLOG_AVAILABLE else logging.Formatter  # type: ignore[misc]
):
    """Extends ``colorlog.ColoredFormatter`` with inline ``[CATEGORY]`` colours."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with both colorlog and category highlighting.

        Args:
            record: The log record to format.

        Returns:
            Formatted string with colour codes.
        """
        return _apply_category_styles(super().format(record))


def setup_logging(
    debug: bool = False,
    log_file: Optional[str] = None,
    log_dir: str = DEFAULT_LOG_DIR,
    max_bytes: int = DEFAULT_MAX_BYTES,
    backup_count: int = DEFAULT_BACKUP_COUNT,
) -> None:
    """Configure the module-level logger with console + optional file output.

    Args:
        debug: Enable DEBUG-level output (default is INFO).
        log_file: Log file name. If given, rotating file handler is added.
        log_dir: Directory for log files. Created automatically.
        max_bytes: Max log file size before rotation.
        backup_count: Number of rotated backup files to keep.
    """
    level = logging.DEBUG if debug else logging.INFO
    log.setLevel(level)
    log.handlers.clear()

    # ── Console handler ──
    if _COLORLOG_AVAILABLE:
        handler: logging.Handler = colorlog.StreamHandler()
        handler.setFormatter(_ColorlogCategoryFormatter(
            "%(log_color)s%(asctime)s [%(levelname)s]%(reset)s %(message)s",
            datefmt="%H:%M:%S",
            log_colors={
                "DEBUG":    "cyan",
                "INFO":     "green",
                "WARNING":  "yellow",
                "ERROR":    "red",
                "CRITICAL": "bold_red",
            },
        ))
    else:
        handler = logging.StreamHandler()
        handler.setFormatter(_CategoryFormatter(
            "%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"
        ))
    log.addHandler(handler)

    # ── File handler (rotating) ──
    if log_file:
        log_path = Path(log_dir) / log_file
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            str(log_path),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            _FILE_LOG_FMT, datefmt=_FILE_LOG_DATEFMT
        ))
        log.addHandler(file_handler)
        log.info("Logging to file: %s", log_path.resolve())
