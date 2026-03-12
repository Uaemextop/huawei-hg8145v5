"""
Command-line interface for the web crawling framework.
"""

import argparse
import logging
import os
import sys
import time
import urllib.parse
from pathlib import Path

from web_crawler.config import (
    DEFAULT_OUTPUT, DEFAULT_MAX_DEPTH, DEFAULT_DELAY,
    DEFAULT_CONCURRENCY, DEFAULT_DOWNLOAD_EXTENSIONS,
    auto_concurrency,
)
from web_crawler.core.crawler import Crawler
from web_crawler.plugins import PluginRegistry
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


def _parse_extensions(raw: str, *, all_as_empty: bool = True) -> frozenset[str]:
    """Parse a comma-separated extension string into a normalised frozenset.

    When *all_as_empty* is True, ``"all"`` or ``""`` returns an empty
    frozenset (meaning "no filter").  Otherwise ``"all"`` expands to a
    built-in list of common binary extensions.
    """
    stripped = raw.strip().lower()
    if stripped in ("all", "") and all_as_empty:
        return frozenset()
    if stripped == "all":
        return frozenset(
            "zip exe rar 7z bin tar gz bz2 xz iso img msi apk ipa "
            "deb rpm jar war ear".split()
        )
    return frozenset(
        f".{e.strip().lstrip('.')}" for e in raw.split(",") if e.strip()
    )


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
    parser.add_argument(
        "--no-check-captcha", dest="skip_captcha_check", action="store_true",
        default=False,
        help="Disable WAF/CAPTCHA protection detection – save pages even if "
             "captcha or WAF signatures are found",
    )
    parser.add_argument(
        "--download-extensions", default=DEFAULT_DOWNLOAD_EXTENSIONS,
        metavar="EXTS",
        help="Comma-separated file extensions to actively seek and prioritize, "
             "or 'all' to download every file type without filtering "
             "(default: all)",
    )
    parser.add_argument(
        "--concurrency", default="auto", metavar="N",
        help="Number of parallel download workers, or 'auto' to detect "
             "from CPU/RAM (default: auto)",
    )
    parser.add_argument(
        "--upload-extensions", default="all", metavar="EXTS",
        help="Comma-separated extensions to upload to the git repo "
             "(e.g. zip,bin,rar), or 'all' to upload every file "
             "(default: all)",
    )
    parser.add_argument(
        "--cf-clearance", default="", metavar="COOKIE",
        help="Cloudflare cf_clearance cookie value obtained from a browser "
             "session. Use this to bypass Cloudflare Managed Challenges "
             "when Playwright is not available.",
    )
    parser.add_argument(
        "--lmsa-email", default="", metavar="EMAIL",
        help="Lenovo ID email for LMSA authentication.  Also readable from "
             "the LMSA_EMAIL environment variable.  Used to obtain a WUST "
             "token from passport.lenovo.com and a JWT for the LMSA API.",
    )
    parser.add_argument(
        "--lmsa-password", default="", metavar="PASSWORD",
        help="Lenovo ID password for LMSA authentication.  Also readable "
             "from the LMSA_PASSWORD environment variable.",
    )
    parser.add_argument(
        "--lmsa-wust", default="", metavar="TOKEN",
        help="Pre-obtained LMSA WUST token.  Skips the Lenovo ID OAuth step "
             "and goes directly to JWT exchange.  Use this when you already "
             "have a valid WUST from a previous session.",
    )
    parser.add_argument(
        "--lmsa-jwt", default="", metavar="GUID:JWT",
        help="Pre-obtained LMSA JWT and GUID from a HAR/proxy capture, "
             "separated by ':'.  Format: GUID:JWT_TOKEN.  Skips OAuth and "
             "token exchange entirely — the captured token is used directly.  "
             "Also readable from the LMSA_JWT environment variable "
             "(same GUID:JWT format).  Example: "
             "--lmsa-jwt 98e2895b-...:Ek6TINIruEV6...",
    )
    parser.add_argument(
        "--lmsa-country", default="", metavar="COUNTRY",
        help="Limit LMSA firmware scan to a single country (e.g. 'Mexico').  "
             "When omitted, all built-in regions are scanned.  Only used "
             "when the target URL is rsddownload-secure.lenovo.com.",
    )
    parser.add_argument(
        "--no-external", dest="allow_external", action="store_false",
        default=True,
        help="Disable downloading media files from external CDN hosts "
             "discovered in the crawled pages",
    )
    parser.add_argument(
        "--skip-media-files", action="store_true", default=False,
        help="Skip downloading media files (video/audio) but still record "
             "their URLs in video_urls.txt",
    )
    parser.add_argument(
        "--skip-download-exts", metavar="EXTS", default="",
        help="Comma-separated file extensions (e.g. zip,exe,rar) for which "
             "the actual file download is skipped.  Instead, a ready-to-run "
             "curl command (including all auth headers) is written to "
             "download_links.txt in the output directory.  "
             "Use 'all' to skip downloading every binary file and only record "
             "their links.  Pre-signed LMSA S3 URLs matching this list are "
             "also recorded directly without queuing.",
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

    # Parse download extensions ("all" = no filtering, download everything)
    dl_exts = _parse_extensions(args.download_extensions)
    if dl_exts:
        log.info("Actively seeking extensions: %s", ", ".join(sorted(dl_exts)))
    else:
        log.info("Download mode: ALL file types (no extension filter)")

    # Resolve concurrency (auto or explicit integer)
    raw_conc = args.concurrency.strip().lower()
    if raw_conc in ("auto", "0", ""):
        concurrency = auto_concurrency()
        log.info("Auto-detected concurrency: %d workers (CPU: %s, RAM-aware)",
                 concurrency, os.cpu_count())
    else:
        try:
            concurrency = int(raw_conc)
        except ValueError:
            log.warning("Invalid --concurrency value '%s', using auto", raw_conc)
            concurrency = auto_concurrency()

    # Parse upload extensions ("all" = push everything to git)
    upload_exts = _parse_extensions(args.upload_extensions)
    if upload_exts:
        log.info("Upload filter: only %s extensions pushed to git",
                 ", ".join(sorted(upload_exts)))

    # ── Plugin registry ─────────────────────────────────────────────
    registry = PluginRegistry()
    registry.discover()
    loaded = sum(len(registry.get_plugins(c)) for c in ("detector", "strategy", "extractor", "processor"))
    if loaded:
        log.info("Loaded %d plugins", loaded)

    # ── LMSA authentication (optional) ──────────────────────────────
    lmsa_session = None
    lmsa_email    = args.lmsa_email    or os.environ.get("LMSA_EMAIL", "")
    lmsa_password = args.lmsa_password or os.environ.get("LMSA_PASSWORD", "")
    lmsa_wust     = args.lmsa_wust     or os.environ.get("LMSA_WUST", "")
    lmsa_jwt_raw  = args.lmsa_jwt      or os.environ.get("LMSA_JWT", "")

    if lmsa_jwt_raw:
        # Direct JWT injection from HAR/proxy capture: GUID:JWT_TOKEN
        try:
            from web_crawler.auth.lmsa import LMSASession
            if ":" not in lmsa_jwt_raw:
                raise ValueError(
                    "--lmsa-jwt value must contain ':' separator "
                    "(format: GUID:JWT_TOKEN)"
                )
            sep = lmsa_jwt_raw.index(":")
            jwt_guid = lmsa_jwt_raw[:sep]
            jwt_token = lmsa_jwt_raw[sep + 1:]
            lmsa_session = LMSASession.from_jwt(
                jwt=jwt_token, guid=jwt_guid, verify_ssl=args.verify_ssl
            )
            log.info(
                "[LMSA] ✓ Session initialised from injected JWT "
                "(GUID: %s…)", jwt_guid[:8]
            )
        except (ValueError, Exception) as exc:
            log.warning(
                "[LMSA] --lmsa-jwt parse error (expected GUID:JWT format): %s",
                exc,
            )

    elif lmsa_wust or lmsa_email:
        try:
            from web_crawler.auth.lenovo_id import LenovoIDAuth
            auth_client = LenovoIDAuth(verify_ssl=args.verify_ssl)
            if lmsa_wust:
                log.info("[LMSA] Using pre-obtained WUST token")
                lmsa_session = auth_client.login_with_wust(lmsa_wust)
            elif lmsa_email and lmsa_password:
                log.info("[LMSA] Authenticating with Lenovo ID: %s", lmsa_email)
                lmsa_session = auth_client.login(lmsa_email, lmsa_password)
            else:
                log.warning(
                    "[LMSA] --lmsa-email provided but --lmsa-password missing "
                    "(also check LMSA_PASSWORD env var)"
                )
            if lmsa_session and lmsa_session.is_authenticated:
                log.info("[LMSA] ✓ Authentication successful — JWT active")
            elif lmsa_session is not None:
                log.warning("[LMSA] Session obtained but not authenticated "
                            "(no JWT) — crawl continues without auth")
        except Exception as exc:
            log.warning("[LMSA] Auth error (continuing without auth): %s", exc)

    # ── LMSA firmware scan ──────────────────────────────────────────
    extra_seed_urls: list[str] = []
    _LMSA_S3_HOST = "rsddownload-secure.lenovo.com"
    if (
        lmsa_session is not None
        and lmsa_session.is_authenticated
        and _LMSA_S3_HOST in target_url
    ):
        log.info(
            "[LMSA] Target is LMSA S3 bucket — scanning firmware API to "
            "discover pre-signed download URLs …"
        )
        try:
            from web_crawler.auth.lmsa import _FIRMWARE_COUNTRIES
            country_filter = getattr(args, "lmsa_country", "")
            if country_filter:
                scan_countries = tuple(
                    c.strip() for c in country_filter.split(",") if c.strip()
                )
                log.info(
                    "[LMSA] Firmware scan limited to %d country/countries: %s",
                    len(scan_countries), ", ".join(scan_countries),
                )
            else:
                scan_countries = _FIRMWARE_COUNTRIES
            resources = lmsa_session.scan_all_firmware(countries=scan_countries)
            url_pairs  = lmsa_session.collect_download_urls(resources)
            log.info(
                "[LMSA] Firmware scan found %d unique download URLs (%d resources)",
                len(url_pairs), len(resources),
            )
            plugin_pairs = lmsa_session.get_plugin_urls()
            if plugin_pairs:
                log.info("[LMSA] Plugin/tool URLs: %d", len(plugin_pairs))

            typed = lmsa_session.collect_download_urls_by_type(resources)
            for cat_name, cat_pairs in typed.items():
                if cat_pairs:
                    typed_path = output_dir / f"lmsa_{cat_name}_urls.txt"
                    with typed_path.open("w", encoding="utf-8") as tf:
                        for dl_url, dl_name in cat_pairs:
                            tf.write(f"{dl_url}\t{dl_name}\n")
                    log.info(
                        "[LMSA] %s URL manifest: %s (%d URLs)",
                        cat_name, typed_path, len(cat_pairs),
                    )
            if plugin_pairs:
                plugin_path = output_dir / "lmsa_plugin_urls.txt"
                with plugin_path.open("w", encoding="utf-8") as pf:
                    for dl_url, dl_name in plugin_pairs:
                        pf.write(f"{dl_url}\t{dl_name}\n")
                log.info(
                    "[LMSA] Plugin URL manifest: %s (%d URLs)",
                    plugin_path, len(plugin_pairs),
                )

            all_pairs = url_pairs + plugin_pairs
            manifest_path = output_dir / "lmsa_firmware_urls.txt"
            with manifest_path.open("w", encoding="utf-8") as mf:
                for dl_url, dl_name in all_pairs:
                    mf.write(f"{dl_url}\t{dl_name}\n")
            log.info("[LMSA] Combined firmware URL manifest saved: %s", manifest_path)
            extra_seed_urls = [u for u, _ in all_pairs]
        except Exception as exc:
            log.warning("[LMSA] Firmware scan failed (continuing): %s", exc)

    # Parse skip_download_exts
    skip_dl_exts_raw = getattr(args, "skip_download_exts", "") or ""
    skip_dl_exts: frozenset[str] | None = None
    if skip_dl_exts_raw.strip().lower() == "all":
        skip_dl_exts = _parse_extensions(skip_dl_exts_raw, all_as_empty=False)
    elif skip_dl_exts_raw.strip():
        skip_dl_exts = frozenset(
            e.strip().lower().lstrip(".") for e in skip_dl_exts_raw.split(",") if e.strip()
        )

    crawler = Crawler(
        start_url=target_url,
        output_dir=output_dir,
        max_depth=args.depth,
        delay=args.delay,
        verify_ssl=args.verify_ssl,
        respect_robots=args.respect_robots,
        force=args.force,
        git_push_every=args.git_push_every,
        skip_captcha_check=args.skip_captcha_check,
        download_extensions=dl_exts,
        concurrency=concurrency,
        upload_extensions=upload_exts,
        debug=args.debug,
        cf_clearance=args.cf_clearance,
        allow_external=args.allow_external,
        skip_media_files=args.skip_media_files,
        skip_download_exts=skip_dl_exts,
        lmsa_session=lmsa_session,
        extra_seed_urls=extra_seed_urls,
        plugin_registry=registry,
    )

    t0 = time.monotonic()
    crawler.run()
    elapsed = time.monotonic() - t0
    log.info("Total elapsed time: %.1f s", elapsed)


if __name__ == "__main__":
    main()
