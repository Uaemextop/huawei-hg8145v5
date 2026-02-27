"""
Command-line interface for the generic web crawler.
"""

import argparse
import logging
import sys
import time
from pathlib import Path

from web_crawler.config import DEFAULT_OUTPUT, DEFAULT_MAX_DEPTH, DEFAULT_DELAY
from web_crawler.core.crawler import Crawler
from web_crawler.utils.log import setup_logging, log

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
        description="Generic web crawler – exhaustively downloads ALL pages "
                    "and assets from a target website with no limits.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m web_crawler https://example.com\n"
            "  python -m web_crawler https://example.com --depth 3\n"
            "  python -m web_crawler https://example.com --output my_site\n"
            "  python -m web_crawler https://example.com --log-file crawl.log\n"
        ),
    )
    parser.add_argument(
        "url",
        help="Target URL to crawl (e.g. https://example.com)",
    )
    parser.add_argument(
        "--output", default=DEFAULT_OUTPUT,
        help=f"Output directory (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--depth", type=int, default=DEFAULT_MAX_DEPTH,
        help=f"Maximum crawl depth (0 = unlimited, default: {DEFAULT_MAX_DEPTH})",
    )
    parser.add_argument(
        "--delay", type=float, default=DEFAULT_DELAY,
        help=f"Delay between requests in seconds (default: {DEFAULT_DELAY})",
    )
    parser.add_argument(
        "--no-verify-ssl", dest="verify_ssl", action="store_false", default=True,
        help="Disable TLS certificate verification",
    )
    parser.add_argument(
        "--no-robots", dest="respect_robots", action="store_false", default=True,
        help="Ignore robots.txt restrictions",
    )
    parser.add_argument(
        "--force", action="store_true", default=False,
        help="Re-download files even if they already exist on disk",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable verbose debug logging",
    )
    parser.add_argument(
        "--log-file",
        help="Write detailed logs to this file (always at DEBUG level)",
    )
    parser.add_argument(
        "--git-push-every", type=int, default=0, metavar="N",
        help="Commit and push crawled files every N saved files (requires git repo in output dir)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    setup_logging(debug=args.debug, log_file=args.log_file)

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

    # Normalise the target URL
    target_url = args.url
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    crawler = Crawler(
        start_url=target_url,
        output_dir=output_dir,
        max_depth=args.depth,
        delay=args.delay,
        verify_ssl=args.verify_ssl,
        respect_robots=args.respect_robots,
        force=args.force,
        git_push_every=args.git_push_every,
    )

    t0 = time.monotonic()
    crawler.run()
    elapsed = time.monotonic() - t0
    log.info("Total elapsed time: %.1f s", elapsed)


if __name__ == "__main__":
    main()
