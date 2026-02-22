"""
Command-line interface for the Huawei HG8145V5 crawler.
"""

import argparse
import logging
import sys
from pathlib import Path

from huawei_crawler.config import DEFAULT_HOST, DEFAULT_OUTPUT, DEFAULT_PASSWORD, DEFAULT_USER
from huawei_crawler.core.crawler import Crawler
from huawei_crawler.utils.log import setup_logging, log

try:
    from tqdm import tqdm as _tqdm  # noqa: F401
    _TQDM_AVAILABLE = True
except ImportError:
    _TQDM_AVAILABLE = False

try:
    import colorlog  # noqa: F401
    _COLORLOG_AVAILABLE = True
except ImportError:
    _COLORLOG_AVAILABLE = False


def parse_args() -> argparse.Namespace:
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
        help="Disable TLS certificate verification",
    )
    parser.add_argument(
        "--force", action="store_true", default=False,
        help="Re-download files even if they already exist on disk",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable verbose debug logging",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    setup_logging(debug=args.debug)

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
