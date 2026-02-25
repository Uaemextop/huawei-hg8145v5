#!/usr/bin/env python3
"""
Huawei HG8145V5 — Web Challenge Password Generator
====================================================

Generates the verification code required for web login when the router
has ``FT_SSMP_PWD_CHALLENGE`` enabled (MEGACABLE2 and other ISP modes).

Algorithm (reverse-engineered from firmware V500R022C00SPC340B019)
-----------------------------------------------------------------

Source: ``libhw_smp_web_base.so!HW_WEB_GetSHAByTime`` at offset 0x12c44

  1. Router formats its current date as ``YYYYMMDD``
     (C format: ``sprintf(buf, "%4u%02u%02u", year, month+1, day)``)
  2. This date string is displayed as ``var randcode = 'YYYYMMDD'``
     in the login page HTML source.
  3. Server computes ``SHA-256(YYYYMMDD)`` and stores the hex digest.
  4. ``WEB_CHALLENGE_CheckVerifyCodeResult`` compares the user's input
     against the first **16 hex characters** of the SHA-256 digest
     (``HW_OS_MemCmp`` with length 0x11 = 17 bytes including null).

  **verification_code = SHA256(YYYYMMDD)[:16]**

How to use
----------

1. Open the router login page (http://192.168.100.1)
2. View the page source or look at the displayed challenge code
3. Find the ``randcode`` value (e.g., ``20260221``)
4. Run this script and enter that date
5. Enter the generated verification code in the login form

Usage::

    python web_challenge_password.py
    python web_challenge_password.py --auto 192.168.100.1
    python web_challenge_password.py --date 20260221
"""

from __future__ import annotations

import hashlib
import re
import sys
from datetime import date, datetime


def sha256_web_challenge(date_str: str) -> str:
    """Compute the web challenge verification code.

    This is the primary algorithm from HW_WEB_GetSHAByTime:
      SHA256(YYYYMMDD) → first 16 hex characters
    """
    return hashlib.sha256(date_str.encode("ascii")).hexdigest()[:16]


def sha256_full(date_str: str) -> str:
    """Full SHA-256 digest (64 hex chars) — fallback if 16-char truncation
    is not accepted by some firmware versions."""
    return hashlib.sha256(date_str.encode("ascii")).hexdigest()


def md5_web_challenge(date_str: str) -> str:
    """MD5 variant — used when HW_SSMP_FEATURE_PASSWDMODE_MD5 is enabled.

    Some older firmware versions or ISP customizations use MD5 instead
    of SHA-256.
    """
    return hashlib.md5(date_str.encode("ascii")).hexdigest()


def validate_date(date_str: str) -> bool:
    """Validate that the input is a valid YYYYMMDD date string."""
    if not date_str.isdigit() or len(date_str) != 8:
        return False
    try:
        datetime.strptime(date_str, "%Y%m%d")
        return True
    except ValueError:
        return False


def fetch_randcode_from_router(ip: str) -> dict:
    """Fetch the randcode and challenge settings from a live router.

    Returns a dict with: randcode, useChallengeCode, CfgMode
    """
    result = {"randcode": None, "useChallengeCode": None, "CfgMode": None}
    try:
        import urllib3
        import requests
        urllib3.disable_warnings()
    except ImportError:
        print("[!] 'requests' library not installed.")
        print("    Install it with: pip install requests")
        return result

    try:
        url = f"http://{ip}/index.asp"
        print(f"[*] Connecting to {url} ...")
        resp = requests.get(url, timeout=10, verify=False)

        m = re.search(r"var\s+randcode\s*=\s*'([^']*)'", resp.text)
        if m:
            result["randcode"] = m.group(1)

        m = re.search(r"var\s+useChallengeCode\s*=\s*'([^']*)'", resp.text)
        if m:
            result["useChallengeCode"] = m.group(1)

        m = re.search(r"var\s+CfgMode\s*=\s*'([^']*)'", resp.text)
        if m:
            result["CfgMode"] = m.group(1)

    except Exception as e:
        print(f"[!] Connection failed: {e}")

    return result


def interactive_mode():
    """Run the script in interactive mode, prompting the user for input."""
    print("=" * 65)
    print("  Huawei HG8145V5 — Web Challenge Password Generator")
    print("  Algorithm: SHA-256(YYYYMMDD) — from firmware RE")
    print("=" * 65)
    print()
    print("  The router login page shows a 'randcode' (date in YYYYMMDD")
    print("  format). This script generates the verification code needed")
    print("  to complete the login.")
    print()

    while True:
        print("-" * 65)
        date_str = input("  Enter the randcode/date (YYYYMMDD) [or 'q' to quit]: ").strip()

        if date_str.lower() in ("q", "quit", "exit"):
            print("  Bye!")
            break

        if not date_str:
            # Use today's date as default
            date_str = date.today().strftime("%Y%m%d")
            print(f"  (Using today's date: {date_str})")

        if not validate_date(date_str):
            print(f"  [!] Invalid date format: '{date_str}'")
            print("  [!] Expected format: YYYYMMDD (e.g., 20260221, 19810101)")
            continue

        # Generate all challenge codes
        sha256_16 = sha256_web_challenge(date_str)
        sha256_64 = sha256_full(date_str)
        md5_32 = md5_web_challenge(date_str)

        print()
        print(f"  Date (randcode):  {date_str}")
        print()
        print("  ┌─────────────────────────────────────────────────────────┐")
        print(f"  │  VERIFICATION CODE:  {sha256_16}                  │")
        print("  └─────────────────────────────────────────────────────────┘")
        print()
        print("  Copy the code above and paste it into the router's")
        print("  verification code field on the login page.")
        print()
        print("  Alternative codes (if the primary one is not accepted):")
        print(f"    SHA-256 full : {sha256_64}")
        print(f"    MD5          : {md5_32}")
        print(f"    SHA-256 8chr : {sha256_16[:8]}")
        print()


def auto_mode(ip: str):
    """Automatically fetch the randcode from the router and generate the code."""
    print("=" * 65)
    print("  Huawei HG8145V5 — Web Challenge Password Generator (Auto)")
    print("=" * 65)
    print()

    info = fetch_randcode_from_router(ip)

    if info["CfgMode"]:
        print(f"  [*] CfgMode           : {info['CfgMode']}")
    if info["useChallengeCode"]:
        enabled = info["useChallengeCode"] == "1"
        print(f"  [*] Challenge enabled : {'Yes' if enabled else 'No'}")
        if not enabled:
            print("  [!] Challenge code is NOT enabled on this router.")
            print("  [!] You can log in with just username + password.")
            return

    if not info["randcode"]:
        print("  [!] Could not fetch randcode from router.")
        print("  [!] Try manual mode: python web_challenge_password.py")
        return

    randcode = info["randcode"]
    print(f"  [*] randcode (date)   : {randcode}")
    print()

    if not validate_date(randcode):
        print(f"  [!] randcode '{randcode}' is not a valid date.")
        print("  [!] The router may not have FT_SSMP_PWD_CHALLENGE enabled.")
        return

    sha256_16 = sha256_web_challenge(randcode)
    sha256_64 = sha256_full(randcode)

    print("  ┌─────────────────────────────────────────────────────────┐")
    print(f"  │  VERIFICATION CODE:  {sha256_16}                  │")
    print("  └─────────────────────────────────────────────────────────┘")
    print()
    print("  Copy the code above and paste it into the router's")
    print("  verification code field on the login page.")
    print()
    print(f"  Full SHA-256: {sha256_64}")
    print()


def cli_mode(date_str: str):
    """Generate the code for a date given on the command line."""
    if not validate_date(date_str):
        print(f"Error: '{date_str}' is not a valid YYYYMMDD date.", file=sys.stderr)
        sys.exit(1)

    sha256_16 = sha256_web_challenge(date_str)
    sha256_64 = sha256_full(date_str)
    md5_32 = md5_web_challenge(date_str)

    print(f"Date:               {date_str}")
    print(f"Verification code:  {sha256_16}")
    print(f"SHA-256 (full):     {sha256_64}")
    print(f"MD5:                {md5_32}")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Huawei HG8145V5 Web Challenge Password Generator",
        epilog="Run without arguments for interactive mode.",
    )
    parser.add_argument(
        "--date", "-d",
        help="Date in YYYYMMDD format (shown as randcode on the login page)",
    )
    parser.add_argument(
        "--auto", "-a",
        metavar="IP",
        help="Auto-fetch randcode from a live router (e.g., 192.168.100.1)",
    )

    args = parser.parse_args()

    if args.auto:
        auto_mode(args.auto)
    elif args.date:
        cli_mode(args.date)
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
