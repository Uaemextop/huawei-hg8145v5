"""
Logging configuration for the crawler.
"""

import logging
from pathlib import Path

try:
    import colorlog
    _COLORLOG_AVAILABLE = True
except ImportError:
    _COLORLOG_AVAILABLE = False

log = logging.getLogger("web-crawler")

_FILE_LOG_FMT = "%(asctime)s [%(levelname)s] %(message)s"
_FILE_LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"

# ANSI escape helpers for inline category colouring (used even without
# colorlog, as long as the terminal supports ANSI codes).
_ANSI_RESET = "\033[0m"
_CATEGORY_STYLES: dict[str, str] = {
    "[PROTECTION]": "\033[1;31m",   # bold red
    "[SOFT-404]":   "\033[33m",     # yellow
    "[WP]":         "\033[1;35m",   # bold magenta
    "[RETRY]":      "\033[36m",     # cyan
    "[SAVE]":       "\033[1;32m",   # bold green
    "[SKIP]":       "\033[90m",     # dim grey
    "[DUP]":        "\033[90m",     # dim grey
    "[ERR]":        "\033[1;31m",   # bold red
    "[GIT]":        "\033[34m",     # blue
    "[QUEUE]":      "\033[37m",     # white
}


def _apply_category_styles(msg: str) -> str:
    """Inject ANSI colours for known ``[CATEGORY]`` tags in *msg*."""
    for tag, style in _CATEGORY_STYLES.items():
        if tag in msg:
            msg = msg.replace(tag, f"{style}{tag}{_ANSI_RESET}")
    return msg


class _CategoryFormatter(logging.Formatter):
    """Formatter that highlights known ``[CATEGORY]`` tags inside log
    messages with distinct ANSI colours."""

    def __init__(self, fmt: str, datefmt: str | None = None) -> None:
        super().__init__(fmt, datefmt=datefmt)

    def format(self, record: logging.LogRecord) -> str:
        return _apply_category_styles(super().format(record))


class _ColorlogCategoryFormatter(colorlog.ColoredFormatter if _COLORLOG_AVAILABLE else logging.Formatter):  # type: ignore[misc]
    """Extends ``colorlog.ColoredFormatter`` to also highlight inline
    ``[CATEGORY]`` tags."""

    def format(self, record: logging.LogRecord) -> str:
        return _apply_category_styles(super().format(record))


def setup_logging(debug: bool = False, log_file: str | None = None) -> None:
    """Configure the module-level logger with optional colour support
    and optional file output.

    Parameters
    ----------
    debug : bool
        Enable DEBUG-level output (default is INFO).
    log_file : str | None
        If given, also write log messages to this file path.
    """
    level = logging.DEBUG if debug else logging.INFO
    log.setLevel(level)
    log.handlers.clear()

    # -- Console handler --
    if _COLORLOG_AVAILABLE:
        handler = colorlog.StreamHandler()
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

    # -- File handler (optional) --
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(str(log_path), encoding="utf-8")
        fh.setLevel(logging.DEBUG)          # always capture full detail
        fh.setFormatter(logging.Formatter(_FILE_LOG_FMT, datefmt=_FILE_LOG_DATEFMT))
        log.addHandler(fh)
        log.info("Logging to file: %s", log_path.resolve())
