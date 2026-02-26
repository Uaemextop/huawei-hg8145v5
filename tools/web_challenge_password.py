#!/usr/bin/env python3
"""
Huawei HG8145V5 — Web Challenge Password Generator
====================================================

Standalone tool — no dependencies on other project scripts.

Generates the verification code required for web login when the router
has ``FT_SSMP_PWD_CHALLENGE`` enabled (MEGACABLE2 and other ISP modes).

Algorithm (reverse-engineered from firmware V500R022C00SPC340B019
and confirmed via Capstone ARM disassembly of V500R020C10SPC212)
-----------------------------------------------------------------

Source: ``libhw_smp_web_base.so!HW_WEB_GetSHAByTime`` @ ``0x186d4``

  1. Router formats its current date as ``YYYYMMDD``
     (C format: ``sprintf(buf, "%4u%02u%02u", year, month+1, day)``)
  2. This date string is displayed as ``var randcode = 'YYYYMMDD'``
     in the login page HTML source.
  3. Server computes ``SHA-256(YYYYMMDD)`` and stores the hex digest.
  4. ``WEB_CHALLENGE_CheckVerifyCodeResult`` compares the user's input
     against the first **16 hex characters** of the SHA-256 digest
     (``HW_OS_MemCmp`` with length 0x11 = 17 bytes including null).

  **verification_code = SHA256(YYYYMMDD)[:16]**

ARM disassembly of ``HW_WEB_GetSHAByTime`` (Capstone-verified)::

    memset(sha_buf, 0, 0x11)   ; 17 bytes (16 hex + null)
    memset(hex_buf, 0, 0x41)   ; 65 bytes (64 hex + null)
    cmp    r4, #1              ; if output_len <= 1, error
    memcpy(sha_buf, input, 17) ; copy "YYYYMMDD" date string
    bl     HW_SHA256_CAL       ; SHA-256(date_string)
    cmp    r4, #0x41           ; min(output_len, 65)
    memcpy(output, hex, len-1) ; copy truncated hex digest

Firmware findings (verified via Capstone disassembly of 3 firmwares)
--------------------------------------------------------------------

Analyzed firmware binaries (full SquashFS extraction + Capstone ARM):

* **V500R022C00SPC340B019** — MEGACABLE production firmware
* **V500R020C10SPC212** — 7004 files, 799 ELF, Linux 4.4.219, ARM Cortex-A9
* **DESBLOQUEIO R22** — Brazil unlock kit (TELNET.bin + UNLOCK.bin)

Key findings:

* AES-128-CBC key for ``hw_ctree.xml`` config file encryption::

    Df7!ui%s9(lmV1L8

  Confirmed in: ``libcfg_api.so:0xb58b``, ``libhw_smp_web_cfg.so:0x1427e``,
  ``bin/aescrypt2:0x307b`` (all three firmware versions).
  Source: ``SPEC_OS_AES_CBC_APP_STR`` in ``spec_default.cfg``

  **Note**: This key is for config file encryption only.  PEM certificate
  private keys (``prvt.key``, ``plugprvt.key``, ``server_key_ssl.pem``) use
  AES-256-CBC with a PEM passphrase derived at runtime by
  ``CERT_GetInfoKeypass`` → ``ADAPTER_GetRestSslKeyPassword`` from
  hardware/chip-specific storage (``HW_KMC_CfgGetKey``).

  The ``aescrypt2`` format files (``serverkey.pem``, ``dropbear_rsa_host_key``)
  also use chip-derived keys via ``HW_CTOOL_GetKeyChipStr``.

* ``aescrypt2`` tool: ``0 = encrypt``, ``1 = decrypt`` (HMAC-SHA256 verified)
* MEGACABLE feature flags (``megacablepwd_ft.cfg``):
  ``FT_SSMP_PWD_CHALLENGE=1``, ``FT_WLAN_MEGACABLEPWD=1``
* Password storage: PassMode=3 (PBKDF2-SHA256 with per-user salt)
* WiFi quality AES key: ``sc189#-_*&1$3cn2`` (IV: ``0201611041646174``)
* TelnetEnable file: ``/mnt/jffs2/TelnetEnable`` containing ``\\n``
* SU public key: RSA-256 bit (trivially factorable) at ``/etc/wap/su_pub_key``
* Plugin libs: ``ADAPTER_GetRestSslKeyPassword``, ``CERT_EncryKeyPass``
  in ``libsrv.so`` and ``libbasic.so`` (kernelapp plugin)

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

# ── Firmware constants ─────────────────────────────────────────────────
# Verified via Capstone ARM disassembly of V500R020C10SPC212 (7004 files)

# AES-128-CBC key for hw_ctree.xml config file encryption
# Found at: libcfg_api.so:0xb58b, libhw_smp_web_cfg.so:0x1427e,
#           bin/aescrypt2:0x307b
# Source: SPEC_OS_AES_CBC_APP_STR in spec_default.cfg
# NOTE: This key is for config file encryption only.
#       PEM private keys use chip-derived passphrases (CERT_GetInfoKeypass)
#       aescrypt2 format files use HW_CTOOL_GetKeyChipStr -> HW_KMC_CfgGetKey
AES_KEY = "Df7!ui%s9(lmV1L8"

# WiFi quality report AES key (from base_amp_spec.cfg)
WIFI_AES_KEY = "sc189#-_*&1$3cn2"
WIFI_AES_IV = "0201611041646174"

# Default serial number (user-provided)
DEFAULT_SN = "4857544347020CB1"  # HWTC47020CB1

# MEGACABLE ISP profile
MEGACABLE_ADMIN_USER = "Mega_gpon"
MEGACABLE_ADMIN_PASSWORD = "admintelecom"

# Feature flags from /etc/wap/customize/common/megacablepwd_ft.cfg
# FT_SSMP_PWD_CHALLENGE = 1 (enabled for MEGACABLE)
# FT_WLAN_MEGACABLEPWD = 1 (enabled for MEGACABLE)
# FT_SSMP_CLI_SU_CHALLENGE = 0 (default off)

# Known factory dates (router shows these when RTC has no NTP sync)
FACTORY_DATES = [
    ("19810101", "Factory default — no NTP sync (most common)"),
    ("19700101", "Unix epoch — some board variants"),
    ("20000101", "Y2K default — older firmwares"),
    ("20240101", "Firmware build year — V500R022"),
]


# ── Challenge algorithms ───────────────────────────────────────────────

def sha256_challenge(date_str: str) -> str:
    """Primary web challenge: SHA-256(YYYYMMDD) first 16 hex chars.

    From ``HW_WEB_GetSHAByTime`` in ``libhw_smp_web_base.so``.
    """
    return hashlib.sha256(date_str.encode("ascii")).hexdigest()[:16]


def sha256_full(date_str: str) -> str:
    """Full SHA-256 digest — fallback if 16-char truncation is rejected."""
    return hashlib.sha256(date_str.encode("ascii")).hexdigest()


def md5_challenge(date_str: str) -> str:
    """MD5 variant — ``HW_SSMP_FEATURE_PASSWDMODE_MD5`` path."""
    return hashlib.md5(date_str.encode("ascii")).hexdigest()


def validate_date(date_str: str) -> bool:
    """Validate YYYYMMDD format."""
    if not date_str.isdigit() or len(date_str) != 8:
        return False
    try:
        datetime.strptime(date_str, "%Y%m%d")
        return True
    except ValueError:
        return False


# ── Router interaction (optional) ──────────────────────────────────────

def fetch_randcode_from_router(ip: str) -> dict:
    """Fetch randcode and challenge settings from a live router."""
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

        for var, key in [("randcode", "randcode"),
                         ("useChallengeCode", "useChallengeCode"),
                         ("CfgMode", "CfgMode")]:
            m = re.search(rf"var\s+{var}\s*=\s*'([^']*)'", resp.text)
            if m:
                result[key] = m.group(1)

    except Exception as e:
        print(f"[!] Connection failed: {e}")

    return result


# ── Output modes ───────────────────────────────────────────────────────

def generate_all_codes(date_str: str) -> list[dict]:
    """Generate all possible verification codes for a date."""
    sha = sha256_full(date_str)
    md5 = md5_challenge(date_str)

    return [
        {"code": sha[:16], "method": "SHA-256(date)[:16]",
         "note": "Primary — HW_WEB_GetSHAByTime", "priority": 1},
        {"code": sha, "method": "SHA-256(date) full",
         "note": "Some firmware versions accept full digest", "priority": 2},
        {"code": md5[:16], "method": "MD5(date)[:16]",
         "note": "HW_SSMP_FEATURE_PASSWDMODE_MD5", "priority": 3},
        {"code": md5, "method": "MD5(date) full",
         "note": "Older firmwares", "priority": 4},
    ]


def interactive_mode():
    """Interactive mode — prompts for input."""
    print()
    print("=" * 65)
    print("  Huawei HG8145V5 — Web Challenge Password Generator")
    print("  Firmware: V500R022 (reverse-engineered)")
    print("=" * 65)
    print()
    print("  The router login page shows a 'randcode' (date YYYYMMDD).")
    print("  This script generates the verification code needed to log in.")
    print()
    print(f"  AES key (from firmware): {AES_KEY}")
    print(f"  Default SN            : {DEFAULT_SN}")
    print(f"  Admin user            : {MEGACABLE_ADMIN_USER}")
    print(f"  Admin password        : {MEGACABLE_ADMIN_PASSWORD}")
    print()

    while True:
        print("-" * 65)
        date_str = input(
            "  Enter the randcode/date (YYYYMMDD) [or 'q' to quit]: "
        ).strip()

        if date_str.lower() in ("q", "quit", "exit"):
            print("  Bye!")
            break

        if not date_str:
            date_str = date.today().strftime("%Y%m%d")
            print(f"  (Using today's date: {date_str})")

        if not validate_date(date_str):
            print(f"  [!] Invalid date format: '{date_str}'")
            print("  [!] Expected YYYYMMDD (e.g., 20260221, 19810101)")
            continue

        codes = generate_all_codes(date_str)

        print()
        print(f"  Date (randcode):  {date_str}")
        print()
        print("  ┌─────────────────────────────────────────────────────────┐")
        print(f"  │  VERIFICATION CODE:  {codes[0]['code']}                  │")
        print("  └─────────────────────────────────────────────────────────┘")
        print()
        print("  Copy the code above and paste it into the router's")
        print("  verification code field on the login page.")
        print()

        print("  Alternative codes (if primary is not accepted):")
        for c in codes[1:]:
            label = c["method"]
            val = c["code"]
            if len(val) > 40:
                val = val[:37] + "..."
            print(f"    {label:<25} {val}")
        print()


def auto_mode(ip: str):
    """Fetch randcode from router and generate verification code."""
    print("=" * 65)
    print("  Huawei HG8145V5 — Web Challenge (Auto)")
    print("=" * 65)
    print()

    info = fetch_randcode_from_router(ip)

    if info["CfgMode"]:
        print(f"  [*] CfgMode           : {info['CfgMode']}")
    if info["useChallengeCode"]:
        enabled = info["useChallengeCode"] == "1"
        print(f"  [*] Challenge enabled : {'Yes' if enabled else 'No'}")
        if not enabled:
            print("  [!] Challenge code is NOT enabled.")
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
        return

    codes = generate_all_codes(randcode)

    print("  ┌─────────────────────────────────────────────────────────┐")
    print(f"  │  VERIFICATION CODE:  {codes[0]['code']}                  │")
    print("  └─────────────────────────────────────────────────────────┘")
    print()
    print(f"  Full SHA-256: {codes[1]['code']}")
    print()


def cli_mode(date_str: str):
    """Non-interactive — output codes for a date."""
    if not validate_date(date_str):
        print(f"Error: '{date_str}' is not a valid YYYYMMDD date.",
              file=sys.stderr)
        sys.exit(1)

    codes = generate_all_codes(date_str)
    print(f"Date:               {date_str}")
    for c in codes:
        print(f"{c['method']:<25} {c['code']}")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Huawei HG8145V5 Web Challenge Password Generator",
        epilog="Run without arguments for interactive mode.",
    )
    parser.add_argument(
        "--date", "-d",
        help="Date in YYYYMMDD format (randcode from the login page)",
    )
    parser.add_argument(
        "--auto", "-a", metavar="IP",
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
