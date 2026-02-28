"""
Logging configuration for the crawler.

Provides a clean logging system with:
* ANSI colour highlights for ``[CATEGORY]`` tags (works with or without ``colorlog``)
* GitHub Actions CI support (``::warning::``, ``::error::``, ``::group::``)
"""

import logging
import os
from pathlib import Path

try:
    import colorlog
    _COLORLOG_AVAILABLE = True
except ImportError:
    _COLORLOG_AVAILABLE = False

log = logging.getLogger("web-crawler")

_FILE_LOG_FMT = "%(asctime)s [%(levelname)s] %(message)s"
_FILE_LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"

# True when running inside GitHub Actions
_CI: bool = os.environ.get("GITHUB_ACTIONS") == "true"

# ── Category colours ───────────────────────────────────────────────
_ANSI_RESET = "\033[0m"
_CATEGORY_STYLES: dict[str, str] = {
    # tag: ansi_colour
    "[PROTECTION]": "\033[1;31m",
    "[SOFT-404]":   "\033[33m",
    "[WP]":         "\033[1;35m",
    "[WP-MEDIA]":   "\033[1;35m",
    "[WP-PLUGIN]":  "\033[1;35m",
    "[WP-THEME]":   "\033[1;35m",
    "[SG-CAPTCHA]": "\033[1;36m",
    "[RETRY]":      "\033[36m",
    "[CF-BYPASS]":  "\033[36m",
    "[SAVE]":       "\033[1;32m",
    "[SKIP]":       "\033[90m",
    "[DUP]":        "\033[90m",
    "[ERR]":        "\033[1;31m",
    "[GIT]":        "\033[34m",
    "[QUEUE]":      "\033[37m",
    "[PROBE]":      "\033[90m",
    "[WAF]":        "\033[1;31m",
    "[429]":        "\033[33m",
}


def _apply_category_styles(msg: str) -> str:
    """Inject ANSI colours for known ``[CATEGORY]`` tags in *msg*."""
    for tag, style in _CATEGORY_STYLES.items():
        if tag in msg:
            msg = msg.replace(tag, f"{style}{tag}{_ANSI_RESET}")
    return msg


# ── GitHub Actions helpers ─────────────────────────────────────────

def ci_group(title: str) -> None:
    """Emit ``::group::`` when running in GitHub Actions (no-op otherwise)."""
    if _CI:
        print(f"::group::{title}", flush=True)


def ci_endgroup() -> None:
    """Emit ``::endgroup::`` when running in GitHub Actions (no-op otherwise)."""
    if _CI:
        print("::endgroup::", flush=True)


# ── Formatters ─────────────────────────────────────────────────────

class _CategoryFormatter(logging.Formatter):
    """Formatter that highlights known ``[CATEGORY]`` tags with
    ANSI colours."""

    def __init__(self, fmt: str, datefmt: str | None = None) -> None:
        super().__init__(fmt, datefmt=datefmt)

    def format(self, record: logging.LogRecord) -> str:
        return _apply_category_styles(super().format(record))


class _ColorlogCategoryFormatter(colorlog.ColoredFormatter if _COLORLOG_AVAILABLE else logging.Formatter):  # type: ignore[misc]
    """Extends ``colorlog.ColoredFormatter`` to also highlight inline
    ``[CATEGORY]`` tags."""

    def format(self, record: logging.LogRecord) -> str:
        return _apply_category_styles(super().format(record))


class _CIFormatter(logging.Formatter):
    """Formatter for GitHub Actions CI environments.

    Emits ``::warning::`` / ``::error::`` workflow commands so that
    warnings and errors appear as annotations in the Actions UI.
    Regular messages keep ANSI category-tag colours.
    """

    _CI_COMMANDS: dict[int, str] = {
        logging.WARNING:  "::warning::",
        logging.ERROR:    "::error::",
        logging.CRITICAL: "::error::",
    }

    def format(self, record: logging.LogRecord) -> str:
        formatted = _apply_category_styles(super().format(record))
        prefix = self._CI_COMMANDS.get(record.levelno, "")
        if prefix:
            return f"{prefix}{formatted}"
        return formatted


def setup_logging(debug: bool = False, log_file: str | None = None) -> None:
    """Configure the module-level logger with optional colour support,
    optional file output, and GitHub Actions CI awareness.

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
    if _CI:
        handler = logging.StreamHandler()
        handler.setFormatter(_CIFormatter(
            "%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"
        ))
    elif _COLORLOG_AVAILABLE:
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
