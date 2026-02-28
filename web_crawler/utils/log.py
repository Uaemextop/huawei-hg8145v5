"""
Logging configuration for the crawler.

Provides a modern logging system with:
* Unicode icons for each log category
* ANSI colour engine (works with or without ``colorlog``)
* Level-specific icons (✓ INFO, ⚠ WARNING, ✗ ERROR, …)
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

# ── Unicode icons for level indicators ──────────────────────────────
_LEVEL_ICONS: dict[int, str] = {
    logging.DEBUG:    "🔍",
    logging.INFO:     "✅",
    logging.WARNING:  "⚠️",
    logging.ERROR:    "❌",
    logging.CRITICAL: "💀",
}

# ── Category icons + colours ────────────────────────────────────────
_ANSI_RESET = "\033[0m"
_CATEGORY_STYLES: dict[str, tuple[str, str]] = {
    # tag: (ansi_colour, icon)
    "[PROTECTION]": ("\033[1;31m", "🛡️ "),
    "[SOFT-404]":   ("\033[33m",   "👻 "),
    "[WP]":         ("\033[1;35m", "📦 "),
    "[WP-MEDIA]":   ("\033[1;35m", "🖼️ "),
    "[WP-PLUGIN]":  ("\033[1;35m", "🔌 "),
    "[WP-THEME]":   ("\033[1;35m", "🎨 "),
    "[SG-CAPTCHA]": ("\033[1;36m", "🔐 "),
    "[RETRY]":      ("\033[36m",   "🔄 "),
    "[CF-BYPASS]":  ("\033[36m",   "☁️ "),
    "[SAVE]":       ("\033[1;32m", "💾 "),
    "[SKIP]":       ("\033[90m",   "⏭️ "),
    "[DUP]":        ("\033[90m",   "♻️ "),
    "[ERR]":        ("\033[1;31m", "❌ "),
    "[GIT]":        ("\033[34m",   "📤 "),
    "[QUEUE]":      ("\033[37m",   "📋 "),
    "[PROBE]":      ("\033[90m",   "🔎 "),
    "[WAF]":        ("\033[1;31m", "🚫 "),
    "[429]":        ("\033[33m",   "⏳ "),
}


def _apply_category_styles(msg: str) -> str:
    """Inject ANSI colours and Unicode icons for known ``[CATEGORY]``
    tags in *msg*."""
    for tag, (style, icon) in _CATEGORY_STYLES.items():
        if tag in msg:
            msg = msg.replace(tag, f"{style}{icon}{tag}{_ANSI_RESET}")
    return msg


class _CategoryFormatter(logging.Formatter):
    """Formatter that adds level icons and highlights known
    ``[CATEGORY]`` tags with colours and Unicode icons."""

    def __init__(self, fmt: str, datefmt: str | None = None) -> None:
        super().__init__(fmt, datefmt=datefmt)

    def format(self, record: logging.LogRecord) -> str:
        icon = _LEVEL_ICONS.get(record.levelno, "")
        formatted = super().format(record)
        # Prepend level icon
        if icon:
            formatted = f"{icon} {formatted}"
        return _apply_category_styles(formatted)


class _ColorlogCategoryFormatter(colorlog.ColoredFormatter if _COLORLOG_AVAILABLE else logging.Formatter):  # type: ignore[misc]
    """Extends ``colorlog.ColoredFormatter`` to also highlight inline
    ``[CATEGORY]`` tags and prepend level icons."""

    def format(self, record: logging.LogRecord) -> str:
        icon = _LEVEL_ICONS.get(record.levelno, "")
        formatted = super().format(record)
        if icon:
            formatted = f"{icon} {formatted}"
        return _apply_category_styles(formatted)


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
