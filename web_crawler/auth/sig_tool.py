"""
Standalone CLI tool: download Lenovo LMSA firmware and analyze signatures.

Downloads firmware files from ``rsddownload-secure.lenovo.com`` and prints
a step-by-step AWS Signature V4 breakdown for every URL.

Two modes of operation
----------------------

**Mode A — direct URL** (pre-signed URL already in hand)::

    python -m web_crawler.auth.sig_tool \\
        "https://rsddownload-secure.lenovo.com/firmware.zip?X-Amz-..."

    # Download to a specific directory:
    python -m web_crawler.auth.sig_tool \\
        "https://rsddownload-secure.lenovo.com/firmware.zip?X-Amz-..." \\
        --output-dir /tmp/firmware

    # Analyze only, do not download:
    python -m web_crawler.auth.sig_tool \\
        "https://rsddownload-secure.lenovo.com/firmware.zip?X-Amz-..." \\
        --no-download

**Mode B — fetch fresh URL from the LMSA API** (requires a live JWT)::

    python -m web_crawler.auth.sig_tool \\
        --lmsa-jwt "GUID:JWT_TOKEN" \\
        --model XT2623-2 --country Mexico \\
        --output-dir /tmp/firmware

    # JWT can also be set via environment variable:
    export LMSA_JWT="GUID:JWT_TOKEN"
    python -m web_crawler.auth.sig_tool --model XT2623-2 --country Mexico

**Signature verification** (requires the AWS Secret Access Key)::

    python -m web_crawler.auth.sig_tool "..." --secret MY_AWS_SECRET

The secret can also be set via the AWS_SECRET_ACCESS_KEY environment variable.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import requests

from web_crawler.auth.aws_sig import (
    curl_command,
    is_presigned_s3_url,
    parse_presigned_s3_url,
    print_analysis,
)
from web_crawler.auth.lmsa import DOWNLOAD_USER_AGENT


# ---------------------------------------------------------------------------
# Download helper
# ---------------------------------------------------------------------------

_CHUNK = 1 << 16   # 64 KiB read chunks


def download_file(
    url: str,
    output_dir: Path,
    *,
    verify_ssl: bool = True,
) -> Path:
    """Stream-download *url* into *output_dir* and return the saved path.

    Uses the same ``User-Agent`` string (IE8) that the LMSA desktop app
    sends for S3 downloads so the bucket policy recognises the request.

    Raises :exc:`requests.HTTPError` when the server returns a non-2xx
    status code (e.g. HTTP 403 when the pre-signed URL has expired).
    """
    filename = url.split("?")[0].rstrip("/").rsplit("/", 1)[-1] or "firmware.bin"
    dest = output_dir / filename

    session = requests.Session()
    session.headers["User-Agent"] = DOWNLOAD_USER_AGENT

    print(f"[DL] GET {url.split('?')[0]}", file=sys.stderr)
    resp = session.get(url, stream=True, verify=verify_ssl, timeout=60)
    resp.raise_for_status()

    total = int(resp.headers.get("Content-Length", 0))
    received = 0
    output_dir.mkdir(parents=True, exist_ok=True)

    with dest.open("wb") as fh:
        for chunk in resp.iter_content(chunk_size=_CHUNK):
            if chunk:
                fh.write(chunk)
                received += len(chunk)
                if total:
                    pct = received * 100 // total
                    bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
                    print(
                        f"\r[DL] [{bar}] {pct:3d}%  "
                        f"{received // (1 << 20)} / {total // (1 << 20)} MB",
                        end="",
                        file=sys.stderr,
                    )

    if total:
        print(file=sys.stderr)   # newline after progress bar
    print(
        f"[DL] Saved {received:,} bytes -> {dest}",
        file=sys.stderr,
    )
    return dest


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m web_crawler.auth.sig_tool",
        description=(
            "Download Lenovo LMSA firmware and analyze its AWS Signature V4 URL."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "url",
        nargs="?",
        default="",
        help=(
            "Pre-signed S3 URL to download/analyze.  "
            "Omit when using --lmsa-jwt to fetch a fresh URL from the API."
        ),
    )
    parser.add_argument(
        "--output-dir", "-o",
        default=".",
        metavar="DIR",
        help="Directory where downloaded files are saved (default: current dir).",
    )
    parser.add_argument(
        "--no-download",
        dest="download",
        action="store_false",
        default=True,
        help="Print the analysis only; do not actually download the file.",
    )
    parser.add_argument(
        "--secret",
        default="",
        metavar="AWS_SECRET_KEY",
        help=(
            "AWS Secret Access Key used to verify the X-Amz-Signature value.  "
            "Also readable from the AWS_SECRET_ACCESS_KEY environment variable."
        ),
    )
    parser.add_argument(
        "--lmsa-jwt",
        default="",
        metavar="GUID:JWT",
        help=(
            "Pre-obtained LMSA JWT and GUID (format: GUID:JWT_TOKEN).  "
            "The tool calls the live LMSA API to get a fresh pre-signed URL "
            "for --model / --country, then downloads and analyzes it.  "
            "Also readable from the LMSA_JWT environment variable."
        ),
    )
    parser.add_argument(
        "--model",
        default="XT2623-2",
        metavar="MODEL",
        help="Device model to query via --lmsa-jwt (default: XT2623-2).",
    )
    parser.add_argument(
        "--country",
        default="Mexico",
        metavar="COUNTRY",
        help="Country for the LMSA firmware query (default: Mexico).",
    )
    parser.add_argument(
        "--no-verify-ssl",
        dest="verify_ssl",
        action="store_false",
        default=True,
        help="Disable TLS certificate verification.",
    )
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# LMSA API helper
# ---------------------------------------------------------------------------

def _fetch_lmsa_urls(
    lmsa_jwt_raw: str,
    model: str,
    country: str,
    verify_ssl: bool,
) -> list[str]:
    """Return fresh pre-signed URLs from the LMSA API for *model*/*country*."""
    from web_crawler.auth.lmsa import LMSASession

    if ":" not in lmsa_jwt_raw:
        raise ValueError(
            "--lmsa-jwt must be in GUID:JWT format "
            "(e.g. 98e2895b-...:Ek6TINIruEV6...)"
        )
    sep = lmsa_jwt_raw.index(":")
    guid = lmsa_jwt_raw[:sep]
    jwt = lmsa_jwt_raw[sep + 1:]

    session = LMSASession.from_jwt(jwt=jwt, guid=guid, verify_ssl=verify_ssl)
    print(f"[LMSA] Session ready (GUID: {guid[:8]}...)", file=sys.stderr)

    resources = session._resolve_resource(model, model, country=country)
    urls: list[str] = []
    for res in resources:
        for key in ("romResource", "toolResource", "otaResource",
                    "countryCodeResource"):
            sub = res.get(key)
            if isinstance(sub, dict) and sub.get("uri"):
                uri = sub["uri"]
                if not uri.startswith(("http://", "https://")):
                    uri = "https://" + uri
                urls.append(uri)
        if res.get("flashFlow"):
            urls.append(res["flashFlow"])

    if not urls:
        print(
            f"[LMSA] No URLs found for model={model!r}, country={country!r}",
            file=sys.stderr,
        )
    return urls


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    secret = args.secret or os.environ.get("AWS_SECRET_ACCESS_KEY", "")
    lmsa_jwt = args.lmsa_jwt or os.environ.get("LMSA_JWT", "")
    output_dir = Path(args.output_dir)

    # ------------------------------------------------------------------ #
    # Collect URLs to process
    # ------------------------------------------------------------------ #
    if lmsa_jwt:
        try:
            urls = _fetch_lmsa_urls(
                lmsa_jwt,
                model=args.model,
                country=args.country,
                verify_ssl=args.verify_ssl,
            )
        except Exception as exc:
            print(f"[ERROR] LMSA API query failed: {exc}", file=sys.stderr)
            return 1
        if not urls:
            return 1

    elif args.url.strip():
        urls = [args.url.strip()]

    else:
        print(
            "Usage: python -m web_crawler.auth.sig_tool <URL> [--output-dir DIR]\n"
            "       python -m web_crawler.auth.sig_tool --lmsa-jwt GUID:JWT "
            "[--model MODEL] [--country COUNTRY] [--output-dir DIR]\n\n"
            "Run with --help for full documentation.",
            file=sys.stderr,
        )
        return 1

    # ------------------------------------------------------------------ #
    # For each URL: analyze + (optionally) download
    # ------------------------------------------------------------------ #
    rc = 0
    for url in urls:
        # Always print the signature analysis
        print_analysis(url, secret_key=secret)
        print()

        # Warn when URL is not pre-signed (cannot download without signing)
        if not is_presigned_s3_url(url):
            print(
                "[WARN] URL has no X-Amz-Signature — "
                "it requires a fresh pre-signed URL from the LMSA API.",
                file=sys.stderr,
            )
            print(f"  {curl_command(url)}")
            print()
            rc = 1
            continue

        if not args.download:
            continue

        try:
            saved = download_file(url, output_dir, verify_ssl=args.verify_ssl)
            print(f"[OK] {saved.name}")
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else "?"
            parsed_url = parse_presigned_s3_url(url)
            expires = parsed_url["expires"] if parsed_url else 604800
            print(
                f"[ERROR] HTTP {status} — download failed.\n"
                f"        The pre-signed URL may have expired "
                f"(X-Amz-Expires={expires}, valid "
                f"{expires // 3600}h from signing date).",
                file=sys.stderr,
            )
            rc = 1
        except Exception as exc:
            print(f"[ERROR] Download failed: {exc}", file=sys.stderr)
            rc = 1

    return rc


if __name__ == "__main__":
    sys.exit(main())
