"""
Centralised logging utilities for the Motorola Firmware Downloader.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Dict, Optional

try:
    import colorlog

    _HAS_COLOR = True
except ImportError:
    _HAS_COLOR = False

_LOGGERS: Dict[str, logging.Logger] = {}


def _resolve_level(level: str | int) -> int:
    """Convert a textual level to the logging module equivalent."""
    if isinstance(level, int):
        return level
    return getattr(logging, str(level).upper(), logging.INFO)


def get_logger(
    name: str,
    level: str | int = "INFO",
    log_file: Optional[str | Path] = None,
    max_bytes: int = 1_048_576,
    backup_count: int = 5,
) -> logging.Logger:
    """Return a configured logger instance.

    Args:
        name: Logger name, typically ``__name__``.
        level: Logging level (e.g. ``"INFO"``).
        log_file: Optional path for file output. When omitted, logs
            are not persisted to disk.
        max_bytes: Maximum log file size before rotation.
        backup_count: Number of rotated log files to keep.

    Returns:
        Configured :class:`logging.Logger` instance.
    """
    if name in _LOGGERS:
        logger = _LOGGERS[name]
        logger.setLevel(_resolve_level(level))
        if log_file:
            _ensure_file_handler(
                logger,
                log_file,
                _resolve_level(level),
                max_bytes,
                backup_count,
            )
        return logger

    logger = logging.getLogger(name)
    logger.setLevel(_resolve_level(level))
    logger.propagate = False

    formatter = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s - %(message)s",
    )

    if _HAS_COLOR:
        color_formatter = colorlog.ColoredFormatter(
            "%(log_color)s%(asctime)s [%(name)s] %(levelname)s%(reset)s - %(message)s",
            log_colors={
                "DEBUG": "cyan",
                "INFO": "green",
                "WARNING": "yellow",
                "ERROR": "red",
                "CRITICAL": "bold_red",
            },
        )
    else:
        color_formatter = formatter

    console_handler = logging.StreamHandler()
    console_handler.setLevel(_resolve_level(level))
    console_handler.setFormatter(color_formatter)
    logger.addHandler(console_handler)

    if log_file:
        _ensure_file_handler(
            logger,
            log_file,
            _resolve_level(level),
            max_bytes,
            backup_count,
            formatter=formatter,
        )

    _LOGGERS[name] = logger
    return logger


def _ensure_file_handler(
    logger: logging.Logger,
    log_file: str | Path,
    level: int,
    max_bytes: int,
    backup_count: int,
    formatter: Optional[logging.Formatter] = None,
) -> None:
    """Attach a rotating file handler if not already present."""
    target = Path(log_file)
    for handler in logger.handlers:
        if isinstance(handler, RotatingFileHandler) and Path(handler.baseFilename) == target:
            return
    target.parent.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(
        target,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter or logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s - %(message)s",
    ))
    logger.addHandler(file_handler)
