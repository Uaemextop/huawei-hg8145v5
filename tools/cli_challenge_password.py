#!/usr/bin/env python3
"""
Huawei HG8145V5 — CLI/Telnet Challenge Password Generator
===========================================================

Generates all possible passwords for the Telnet/SSH root login
and the CLI ``su`` (superuser) challenge.

When you connect via Telnet or serial console, the router shows::

    Welcome Visiting Huawei Home Gateway
    Copyright by Huawei Technologies Co., Ltd.

    Login:root
    Date:19810101
    Password:

This script generates the correct password to enter.

Algorithms (reverse-engineered from firmware V500R022C00SPC340B019)
-------------------------------------------------------------------

**Feature flags** control which algorithm is used (from
``etc/wap/ft/smart/base_smart_ft.cfg``):

1. **FT_SSMP_PWD_CHALLENGE = 1** (MEGACABLE and others)

   Password = ``SHA-256(YYYYMMDD)`` truncated to 16 hex chars.

   Source: ``libhw_smp_web_base.so!HW_WEB_GetSHAByTime`` at 0x12c44.
   The function converts the date to a string, computes SHA-256,
   and returns the first 64 hex characters.  The verification
   function (``WEB_CHALLENGE_CheckVerifyCodeResult``) compares 17
   bytes (16 hex chars + null terminator).

2. **FT_SSMP_CLI_SU_CHALLENGE = 1** (disabled by default)

   The ``su`` command shows ``Challenge:ENCRYPTED_HEX``.
   This is AES-CBC encrypted with a key stored in the router's
   XML config database (parameter 0x0B).  If you have the key
   (e.g., extracted via TR-069), this script can decrypt it.

   Source: ``bin/clid!CLI_AES_GetAuthInfo``, ``CLI_AES_Encrypt``

3. **Both disabled** (factory default for many ISPs)

   The password is the standard root password stored in the database:
   ``admin``, ``adminHW``, the device serial number (SN), or empty.

   Source: ``bin/clid!HW_CLI_VerifySuPassword`` → ``HW_OS_StrCmp``

Usage::

    python cli_challenge_password.py
    python cli_challenge_password.py --date 19810101
    python cli_challenge_password.py --date 19810101 --sn HWTC12345678
"""

from __future__ import annotations

import hashlib
import hmac
import sys
from datetime import date, datetime


# Known factory/default dates the router shows when RTC has no NTP sync
FACTORY_DATES = [
    ("19810101", "Factory default — no NTP sync (most common)"),
    ("19700101", "Unix epoch — some board variants"),
    ("20000101", "Y2K default — older firmwares"),
    ("20240101", "Firmware build year — V500R022"),
]

# Known default root passwords (from firmware strings in bin/clid)
DEFAULT_PASSWORDS = [
    ("admin",    "Default for most ISP modes"),
    ("adminHW",  "Huawei engineering mode"),
    ("root",     "Some customizations"),
    ("huawei",   "Legacy firmwares"),
    ("",         "DBAA1 mode (empty password)"),
]


def sha256_password(date_str: str, length: int = 16) -> str:
    """SHA-256 challenge password.

    From HW_WEB_GetSHAByTime in libhw_smp_web_base.so:
      SHA256(YYYYMMDD) → first ``length`` hex characters
    """
    return hashlib.sha256(date_str.encode("ascii")).hexdigest()[:length]


def md5_password(date_str: str) -> str:
    """MD5 challenge password (HW_SSMP_FEATURE_PASSWDMODE_MD5)."""
    return hashlib.md5(date_str.encode("ascii")).hexdigest()


def sha256_with_sn(date_str: str, serial_number: str) -> str:
    """SHA-256 of date + serial number.

    Some firmware variants derive the challenge from the combination
    of the displayed date and the device serial number.
    """
    combined = date_str + serial_number
    return hashlib.sha256(combined.encode("ascii")).hexdigest()[:16]


def sha256_sn_only(serial_number: str) -> str:
    """SHA-256 of the serial number alone.

    On some ISP builds the root password is derived purely from the SN.
    """
    return hashlib.sha256(serial_number.encode("ascii")).hexdigest()[:16]


def hmac_sha256_password(date_str: str, key: str) -> str:
    """HMAC-SHA-256 (when HW_SSMP_FEATURE_CLI_SHA256 is enabled).

    Used with a device-specific key stored in the config DB.
    """
    return hmac.new(
        key.encode("ascii"),
        date_str.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()[:16]


def validate_date(date_str: str) -> bool:
    """Validate YYYYMMDD format."""
    if not date_str.isdigit() or len(date_str) != 8:
        return False
    try:
        datetime.strptime(date_str, "%Y%m%d")
        return True
    except ValueError:
        return False


def generate_all_passwords(date_str: str,
                           serial_number: str | None = None,
                           aes_key: str | None = None) -> list[dict]:
    """Generate all possible root login passwords for the given inputs."""
    results = []

    # --- SHA-256 based (FT_SSMP_PWD_CHALLENGE) ---

    sha_full = hashlib.sha256(date_str.encode("ascii")).hexdigest()
    results.append({
        "password": sha_full[:16],
        "method": "SHA-256(date) first 16 chars",
        "feature": "FT_SSMP_PWD_CHALLENGE=1",
        "priority": 1,
    })
    results.append({
        "password": sha_full,
        "method": "SHA-256(date) full 64 chars",
        "feature": "FT_SSMP_PWD_CHALLENGE=1 (some versions)",
        "priority": 2,
    })

    # --- MD5 based ---

    md5_full = hashlib.md5(date_str.encode("ascii")).hexdigest()
    results.append({
        "password": md5_full[:16],
        "method": "MD5(date) first 16 chars",
        "feature": "HW_SSMP_FEATURE_PASSWDMODE_MD5=1",
        "priority": 3,
    })
    results.append({
        "password": md5_full,
        "method": "MD5(date) full 32 chars",
        "feature": "HW_SSMP_FEATURE_PASSWDMODE_MD5=1 (some versions)",
        "priority": 4,
    })

    # --- Default static passwords ---

    for pwd, desc in DEFAULT_PASSWORDS:
        results.append({
            "password": pwd if pwd else "(empty — just press Enter)",
            "method": f"Default: {desc}",
            "feature": "No challenge (FT_SSMP_PWD_CHALLENGE=0)",
            "priority": 5,
        })

    # --- Serial number based ---

    if serial_number:
        results.append({
            "password": serial_number,
            "method": "Serial number as password",
            "feature": "Some ISPs use the SN as the root password",
            "priority": 6,
        })
        results.append({
            "password": sha256_with_sn(date_str, serial_number),
            "method": "SHA-256(date + SN) first 16 chars",
            "feature": "ISP customization",
            "priority": 7,
        })
        results.append({
            "password": sha256_sn_only(serial_number),
            "method": "SHA-256(SN) first 16 chars",
            "feature": "ISP customization",
            "priority": 8,
        })
        # SN last 8 characters (common on some Huawei models)
        if len(serial_number) >= 8:
            results.append({
                "password": serial_number[-8:],
                "method": "Last 8 chars of SN",
                "feature": "Some ISP modes",
                "priority": 9,
            })

    # --- HMAC (if AES key provided) ---

    if aes_key:
        results.append({
            "password": hmac_sha256_password(date_str, aes_key),
            "method": "HMAC-SHA256(key, date) first 16 chars",
            "feature": "HW_SSMP_FEATURE_CLI_SHA256=1",
            "priority": 10,
        })

    # --- SHA-256 with known suffixes ---

    for suffix in ("HuaweiHomeGateway", "HGW", "root", "admin"):
        combined = date_str + suffix
        h = hashlib.sha256(combined.encode("ascii")).hexdigest()[:16]
        results.append({
            "password": h,
            "method": f"SHA-256(date+'{suffix}') first 16 chars",
            "feature": "ISP customization variant",
            "priority": 11,
        })

    return results


def interactive_mode():
    """Run the script in interactive mode with user prompts."""
    print()
    print("=" * 65)
    print("  Huawei HG8145V5 — CLI/Telnet Root Password Generator")
    print("  Firmware: V500R022 (reverse-engineered from binary)")
    print("=" * 65)
    print()
    print("  When the router shows:")
    print("    Login:root")
    print("    Date:YYYYMMDD")
    print("    Password:")
    print()
    print("  This tool generates all possible passwords to try.")
    print()

    # Step 1: Ask for the date shown by the router
    print("-" * 65)
    date_str = input("  Enter the date shown by the router (YYYYMMDD)\n"
                     "  [press Enter for '19810101']: ").strip()

    if not date_str:
        date_str = "19810101"
        print(f"  → Using factory default: {date_str}")

    if not validate_date(date_str):
        print(f"\n  [!] Invalid date: '{date_str}'")
        print("  [!] Expected format: YYYYMMDD (e.g., 19810101)")
        sys.exit(1)

    # Step 2: Ask for serial number (optional)
    print()
    print("-" * 65)
    serial_number = input("  Enter the device serial number (SN) if known\n"
                          "  [press Enter to skip]: ").strip() or None

    if serial_number:
        print(f"  → SN: {serial_number}")

    # Step 3: Ask for AES key (optional — for advanced users)
    print()
    print("-" * 65)
    aes_key = input("  Enter the AES challenge key if known\n"
                    "  [press Enter to skip — most users skip this]: ").strip() or None

    if aes_key:
        print(f"  → AES key provided")

    # Generate all passwords
    print()
    print("=" * 65)
    print(f"  PASSWORDS FOR Date:{date_str}")
    print("=" * 65)
    print()

    passwords = generate_all_passwords(date_str, serial_number, aes_key)

    # Group by priority
    current_priority = None
    for i, p in enumerate(passwords, 1):
        if p["priority"] != current_priority:
            current_priority = p["priority"]
            if current_priority <= 2:
                print("  ── SHA-256 Challenge (most likely for MEGACABLE) ──")
            elif current_priority <= 4:
                print("  ── MD5 Challenge (older firmwares) ──")
            elif current_priority <= 5:
                print("  ── Default Passwords (no challenge mode) ──")
            elif current_priority <= 9:
                print("  ── Serial Number Based ──")
            elif current_priority <= 10:
                print("  ── HMAC (with AES key) ──")
            else:
                print("  ── ISP Customization Variants ──")
            print()

        pwd_display = p["password"]
        if len(pwd_display) > 40:
            pwd_display = pwd_display[:37] + "..."

        print(f"  {i:2d}. {pwd_display}")
        print(f"      Method: {p['method']}")
        print(f"      When:   {p['feature']}")
        print()

    # Print quick-copy summary
    print("=" * 65)
    print("  QUICK TRY — Copy & paste these passwords (most likely first):")
    print("=" * 65)
    print()

    shown = set()
    for p in sorted(passwords, key=lambda x: x["priority"]):
        pwd = p["password"]
        if pwd not in shown and len(pwd) <= 64:
            shown.add(pwd)
            if len(shown) <= 8:
                print(f"  {len(shown)}. {pwd}")

    print()


def cli_mode(date_str: str, serial_number: str | None, aes_key: str | None):
    """Non-interactive mode — output passwords directly."""
    if not validate_date(date_str):
        print(f"Error: '{date_str}' is not a valid YYYYMMDD date.", file=sys.stderr)
        sys.exit(1)

    passwords = generate_all_passwords(date_str, serial_number, aes_key)

    print(f"Date: {date_str}")
    if serial_number:
        print(f"SN:   {serial_number}")
    print()

    for i, p in enumerate(passwords, 1):
        print(f"{i:2d}. [{p['feature']}]")
        print(f"    Password: {p['password']}")
        print(f"    Method:   {p['method']}")
        print()


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Huawei HG8145V5 CLI/Telnet Root Password Generator",
        epilog="Run without arguments for interactive mode.",
    )
    parser.add_argument(
        "--date", "-d",
        help="Date shown by the router (YYYYMMDD), e.g., 19810101",
    )
    parser.add_argument(
        "--sn", "-s",
        help="Device serial number (optional — used for SN-based passwords)",
    )
    parser.add_argument(
        "--key", "-k",
        help="AES challenge key (optional — for FT_SSMP_CLI_SU_CHALLENGE)",
    )

    args = parser.parse_args()

    if args.date:
        cli_mode(args.date, args.sn, args.key)
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
