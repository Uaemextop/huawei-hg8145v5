"""
Standalone CLI tool for AWS Signature V4 pre-signed URL analysis.

Analyzes any pre-signed S3 URL captured from the Lenovo LMSA service
(``rsddownload-secure.lenovo.com``) and prints:

  * Every component extracted from the URL
  * The canonical request (Task 1)
  * The string-to-sign (Task 2)
  * The signing-key derivation chain (Task 3)
  * The expected signature when ``--secret`` is supplied
  * A ready-to-run ``curl`` command to download the file

When ``--lmsa-jwt GUID:JWT`` is provided the tool also queries the live
LMSA API for a fresh pre-signed URL for the requested model and analyses
that URL automatically.

Usage examples
--------------
Analyze a captured URL::

    python -m web_crawler.auth.sig_tool \\
        "https://rsddownload-secure.lenovo.com/firmware.zip?X-Amz-..."

Analyze + verify signature (secret key required)::

    python -m web_crawler.auth.sig_tool \\
        "https://rsddownload-secure.lenovo.com/firmware.zip?X-Amz-..." \\
        --secret MY_AWS_SECRET_KEY

Fetch a fresh URL from the LMSA API and analyze it::

    python -m web_crawler.auth.sig_tool \\
        --lmsa-jwt "GUID:JWT_TOKEN" \\
        --model XT2623-2 --country Mexico
"""

from __future__ import annotations

import argparse
import os
import sys

from web_crawler.auth.aws_sig import curl_command, is_presigned_s3_url, print_analysis


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m web_crawler.auth.sig_tool",
        description=(
            "Analyze AWS Signature V4 pre-signed S3 URLs "
            "from the Lenovo LMSA firmware download service."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "url",
        nargs="?",
        default="",
        help=(
            "Pre-signed S3 URL to analyze.  "
            "Omit when using --lmsa-jwt to fetch a fresh URL."
        ),
    )
    parser.add_argument(
        "--secret",
        default="",
        metavar="AWS_SECRET_KEY",
        help=(
            "AWS Secret Access Key to verify the signature.  "
            "When provided the tool computes the expected X-Amz-Signature "
            "and checks it against the captured value.  "
            "Also readable from the AWS_SECRET_ACCESS_KEY environment variable."
        ),
    )
    parser.add_argument(
        "--lmsa-jwt",
        default="",
        metavar="GUID:JWT",
        help=(
            "Pre-obtained LMSA JWT and GUID from a HAR/proxy capture "
            "(format: GUID:JWT_TOKEN).  "
            "When supplied the tool calls the live LMSA API to obtain a "
            "fresh pre-signed URL for --model / --country and analyzes it.  "
            "Also readable from the LMSA_JWT environment variable."
        ),
    )
    parser.add_argument(
        "--model",
        default="XT2623-2",
        metavar="MODEL",
        help="Device model name to query via --lmsa-jwt (default: XT2623-2).",
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


def _fetch_lmsa_url(
    lmsa_jwt_raw: str,
    model: str,
    country: str,
    verify_ssl: bool,
) -> list[str]:
    """Return fresh pre-signed URLs from the LMSA API.

    Authenticates using the supplied ``GUID:JWT`` token, queries
    ``getResource.jhtml`` for *model* / *country*, and returns every
    pre-signed URL found in the response.
    """
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
    print(
        f"[LMSA] Session initialised (GUID: {guid[:8]}…)",
        file=sys.stderr,
    )

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
            f"[LMSA] No download URLs found for model={model!r}, "
            f"country={country!r}",
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

    # ------------------------------------------------------------------ #
    # Mode A: fetch fresh URL(s) from LMSA API then analyze each
    # ------------------------------------------------------------------ #
    if lmsa_jwt:
        try:
            urls = _fetch_lmsa_url(
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

        for url in urls:
            print_analysis(url, secret_key=secret)
            print()
        return 0

    # ------------------------------------------------------------------ #
    # Mode B: analyze a URL supplied on the command line
    # ------------------------------------------------------------------ #
    url = args.url.strip()
    if not url:
        print(
            "Usage: python -m web_crawler.auth.sig_tool <URL> [--secret KEY]\n"
            "       python -m web_crawler.auth.sig_tool --lmsa-jwt GUID:JWT "
            "[--model MODEL] [--country COUNTRY]\n\n"
            "Run with --help for full documentation.",
            file=sys.stderr,
        )
        return 1

    print_analysis(url, secret_key=secret)

    # If the URL is not pre-signed, also show the plain curl command.
    if not is_presigned_s3_url(url):
        cmd = curl_command(url)
        if cmd:
            print()
            print("Note: this URL has no X-Amz-Signature — it requires a fresh")
            print("pre-signed URL from the LMSA API before it can be downloaded.")
            print()
            print("Plain curl (will return HTTP 403 without signing):")
            print(f"  {cmd}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
