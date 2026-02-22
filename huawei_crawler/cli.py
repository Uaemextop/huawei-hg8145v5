"""
Command-line interface for the Huawei HG8145V5 crawler.

Provides argument parsing and main execution flow.
"""

import argparse
import logging
import os
import sys
from pathlib import Path

try:
    import colorlog
    _COLORLOG_AVAILABLE = True
except ImportError:
    _COLORLOG_AVAILABLE = False

try:
    from tqdm import tqdm as _tqdm
    _TQDM_AVAILABLE = True
except ImportError:
    _TQDM_AVAILABLE = False

from huawei_crawler.crawler.core import Crawler


# Configuration constants
DEFAULT_HOST = "192.168.100.1"
DEFAULT_USER = os.environ.get("ROUTER_USER", "Mega_gpon")
DEFAULT_PASSWORD = os.environ.get("ROUTER_PASSWORD", "")
DEFAULT_OUTPUT = "downloaded_site"

log = logging.getLogger("hg8145v5-crawler")


def _setup_logging(debug: bool = False) -> None:
    """
    Configure logging with colored output when available.

    Args:
        debug: Enable debug-level logging
    """
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


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description="Huawei HG8145V5 router admin-panel crawler – "
                    "exhaustively downloads all pages and assets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Password can also be provided via the ROUTER_PASSWORD env var.\n"
            "If the password is not supplied and not in the environment, "
            "you will be prompted for it."
        ),
    )
    parser.add_argument(
        "--host", default=DEFAULT_HOST,
        help=f"Router IP address (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--user", default=DEFAULT_USER,
        help=f"Admin username (default: {DEFAULT_USER})",
    )
    parser.add_argument(
        "--password", default=DEFAULT_PASSWORD,
        help="Admin password (overrides ROUTER_PASSWORD env var)",
    )
    parser.add_argument(
        "--output", default=DEFAULT_OUTPUT,
        help=f"Output directory (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--no-verify-ssl", dest="verify_ssl", action="store_false", default=True,
        help="Disable TLS certificate verification (use for self-signed certs)",
    )
    parser.add_argument(
        "--force", action="store_true", default=False,
        help="Re-download files even if they already exist on disk "
             "(default: skip existing files and parse them for new links)",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable verbose debug logging",
    )
    return parser.parse_args()


def main() -> None:
    """
    Main entry point for the crawler CLI.
    """
    args = parse_args()

    _setup_logging(debug=args.debug)

    if args.debug:
        logging.getLogger("urllib3").setLevel(logging.DEBUG)

    if not args.verify_ssl:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
        log.warning("TLS certificate verification is DISABLED (--no-verify-ssl)")

    if not _TQDM_AVAILABLE:
        log.info("Tip: install tqdm for a live progress bar  (pip install tqdm)")
    if not _COLORLOG_AVAILABLE:
        log.info("Tip: install colorlog for colored output   (pip install colorlog)")

    if not args.password:
        import getpass
        args.password = getpass.getpass("Router password: ")

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    crawler = Crawler(
        host=args.host,
        username=args.user,
        password=args.password,
        output_dir=output_dir,
        verify_ssl=args.verify_ssl,
        force=args.force,
    )
    crawler.run()


if __name__ == "__main__":
    main()
