"""
Logging configuration for the crawler.
"""

import logging

try:
    import colorlog
    _COLORLOG_AVAILABLE = True
except ImportError:
    _COLORLOG_AVAILABLE = False

log = logging.getLogger("web-crawler")


def setup_logging(debug: bool = False) -> None:
    """Configure the module-level logger with optional colour support."""
    level = logging.DEBUG if debug else logging.INFO
    log.setLevel(level)
    log.handlers.clear()

    if _COLORLOG_AVAILABLE:
        handler = colorlog.StreamHandler()
        handler.setFormatter(colorlog.ColoredFormatter(
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
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"
        ))
    log.addHandler(handler)
