#!/usr/bin/env python3
"""
Huawei HG8145V5 — CLI/Telnet Challenge Password Generator
===========================================================

Standalone tool — no dependencies on other project scripts.

Generates all possible passwords for the Telnet/SSH root login
and the CLI ``su`` (superuser) challenge.

When you connect via Telnet or serial console, the router shows::

    Welcome Visiting Huawei Home Gateway
    Copyright by Huawei Technologies Co., Ltd.

    Login:root
    Date:19810101
    Password:

This script generates the correct password to enter.

Algorithms (reverse-engineered from firmware V500R022C00SPC340B019
and confirmed via Capstone ARM disassembly of V500R020C10SPC212)
-------------------------------------------------------------------

1. **FT_SSMP_PWD_CHALLENGE = 1** — ``SHA-256(YYYYMMDD)[:16]``
2. **HW_SSMP_FEATURE_PASSWDMODE_MD5 = 1** — ``MD5(YYYYMMDD)``
3. **Both disabled** — static password (admin, adminHW, SN, or empty)
4. **FT_SSMP_CLI_SU_CHALLENGE = 1** — AES-CBC challenge (disabled by
   default; requires key from XML DB parameter 0x0B)

ARM disassembly of ``HW_WEB_GetSHAByTime`` @ ``0x186d4`` (Capstone)::

    memset(sha_buf, 0, 0x11)   ; 17 bytes
    memset(hex_buf, 0, 0x41)   ; 65 bytes
    memcpy(sha_buf, input, 17) ; "YYYYMMDD"
    bl     HW_SHA256_CAL       ; SHA-256
    memcpy(output, hex, min(output_len, 65)-1)

Firmware findings (verified via Capstone ARM disassembly of 3 firmwares)
------------------------------------------------------------------------

Analyzed firmware binaries (full SquashFS extraction + Capstone ARM):

* **V500R022C00SPC340B019** — MEGACABLE production (squashfs extracted)
* **V500R020C10SPC212** — 7004 files, 799 ELF, Linux 4.4.219, Cortex-A9
* **DESBLOQUEIO R22** — Brazil unlock kit (TELNET.bin + UNLOCK.bin
  with embedded shell scripts and default config XML)

* AES-128-CBC key for ``hw_ctree.xml`` config file encryption::

    Df7!ui%s9(lmV1L8

  Confirmed at: ``libcfg_api.so:0xb58b``, ``libhw_smp_web_cfg.so:0x1427e``,
  ``bin/aescrypt2:0x307b``.
  Source: ``SPEC_OS_AES_CBC_APP_STR`` in ``spec_default.cfg``

  **Note**: This key is for config file encryption only.
  PEM private keys use chip-derived passphrases via ``CERT_GetInfoKeypass``.
  aescrypt2 format files use ``HW_CTOOL_GetKeyChipStr`` → ``HW_KMC_CfgGetKey``.

* ``$2`` encoding (``HW_AES_AscVisible``/``HW_AES_AscUnvisible``)::

    encode: byte + 0x21; if result == '?' (0x3F) → '~' (0x7E)
    decode: if char == '~' → 0x1E; else → char - 0x21

* PassMode=3 → PBKDF2-SHA256 with per-user salt (web/CLI login)
* EncryptMode=2 → ``$2`` prefix (config file at rest)
* MEGACABLE feature flags (``megacablepwd_ft.cfg``):
  ``FT_SSMP_PWD_CHALLENGE=1``, ``FT_WLAN_MEGACABLEPWD=1``
* WiFi quality report AES key: ``sc189#-_*&1$3cn2``
  (IV: ``0201611041646174``, from ``base_amp_spec.cfg``)
* SU public key: RSA-256 bit (trivially factorable) at ``/etc/wap/su_pub_key``
  - Modulus: ``0xcdb6cda2...`` (93047119368797069533900709356153666374...)
  - Used by ``HW_CLI_VerifySuPassword`` @ ``0xcc14`` in ``bin/clid``
* Plugin binaries (kernelapp) contain ``ADAPTER_GetRestSslKeyPassword``,
  ``CERT_EncryKeyPass`` — PEM passphrase is hardware-derived, not static
* UNLOCK.bin sets ``hw_boardinfo`` obj 0x00000001 = "1" and
  obj 0x00000059 = "1" then runs ``restorehwmode.sh``

Users discovered in config backup
----------------------------------

* **Mega_gpon** (admin, UserLevel=0) — password: ``admintelecom``
* **user** (UserLevel=1)
* **Meg4_root** (CLI root, EncryptMode=2)
* **AdminGPON** (TR-069 ACS username)
* **ONTconnect** (TR-069 connection request)

Usage::

    python cli_challenge_password.py
    python cli_challenge_password.py --date 19810101
    python cli_challenge_password.py --date 19810101 --sn HWTC47020CB1
"""

from __future__ import annotations

import hashlib
import hmac
import sys
from datetime import date, datetime

# ── Firmware constants ─────────────────────────────────────────────────

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

# User's default SN
DEFAULT_SN = "4857544347020CB1"          # hex form
DEFAULT_SN_ASCII = "HWTC47020CB1"        # printable form

# MEGACABLE admin credentials (plaintext)
MEGACABLE_ADMIN_USER = "Mega_gpon"
MEGACABLE_ADMIN_PASSWORD = "admintelecom"

# CLI root user
CLI_ROOT_USER = "Meg4_root"

# Known factory/default dates the router shows when RTC has no NTP sync
FACTORY_DATES = [
    ("19810101", "Factory default — no NTP sync (most common)"),
    ("19700101", "Unix epoch — some board variants"),
    ("20000101", "Y2K default — older firmwares"),
    ("20240101", "Firmware build year — V500R022"),
]

# Known default root passwords (from firmware strings in bin/clid)
DEFAULT_PASSWORDS = [
    (MEGACABLE_ADMIN_PASSWORD, "MEGACABLE admin (Mega_gpon)"),
    ("admin",    "Default for most ISP modes"),
    ("adminHW",  "Huawei engineering mode"),
    ("root",     "Some customizations"),
    ("huawei",   "Legacy firmwares"),
    ("",         "DBAA1 mode (empty password)"),
]


# ── Challenge algorithms ───────────────────────────────────────────────

def sha256_password(date_str: str, length: int = 16) -> str:
    """SHA-256 challenge password.

    From ``HW_WEB_GetSHAByTime`` in ``libhw_smp_web_base.so``:
      SHA256(YYYYMMDD) → first ``length`` hex characters
    """
    return hashlib.sha256(date_str.encode("ascii")).hexdigest()[:length]


def md5_password(date_str: str) -> str:
    """MD5 challenge password (``HW_SSMP_FEATURE_PASSWDMODE_MD5``)."""
    return hashlib.md5(date_str.encode("ascii")).hexdigest()


def sha256_with_sn(date_str: str, serial_number: str) -> str:
    """SHA-256 of date + serial number (ISP customization)."""
    combined = date_str + serial_number
    return hashlib.sha256(combined.encode("ascii")).hexdigest()[:16]


def sha256_sn_only(serial_number: str) -> str:
    """SHA-256 of the serial number alone."""
    return hashlib.sha256(serial_number.encode("ascii")).hexdigest()[:16]


def hmac_sha256_password(date_str: str, key: str) -> str:
    """HMAC-SHA-256 (``HW_SSMP_FEATURE_CLI_SHA256``)."""
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


# ── $2 password decoder ───────────────────────────────────────────────

def asc_unvisible(encoded: str) -> bytes:
    """Decode Huawei ``HW_AES_AscUnvisible`` printable encoding.

    From ``libhw_ssp_basic.so`` at 0x92084::

        if char == '~' (0x7E) → byte = 0x1E
        else                  → byte = char - 0x21
    """
    result = bytearray()
    for ch in encoded:
        if ch == "~":
            result.append(0x1E)
        else:
            result.append(ord(ch) - 0x21)
    return bytes(result)


def asc_visible(raw: bytes) -> str:
    """Encode binary to Huawei ``HW_AES_AscVisible`` printable format.

    From ``libhw_ssp_basic.so`` at 0x92170::

        encoded = (byte + 0x21) & 0xFF
        if encoded == '?' (0x3F) → '~' (0x7E)
    """
    result = []
    for b in raw:
        ch = (b + 0x21) & 0xFF
        if ch == 0x3F:  # '?'
            ch = 0x7E   # '~'
        result.append(chr(ch))
    return "".join(result)


# ── Password generation ───────────────────────────────────────────────

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


# ── Display modes ──────────────────────────────────────────────────────

def interactive_mode():
    """Interactive mode with user prompts."""
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
    print(f"  AES key (firmware)   : {AES_KEY}")
    print(f"  Admin user           : {MEGACABLE_ADMIN_USER}")
    print(f"  Admin password       : {MEGACABLE_ADMIN_PASSWORD}")
    print()

    # Step 1: Date
    print("-" * 65)
    date_str = input("  Enter the date shown by the router (YYYYMMDD)\n"
                     "  [press Enter for '19810101']: ").strip()

    if not date_str:
        date_str = "19810101"
        print(f"  -> Using factory default: {date_str}")

    if not validate_date(date_str):
        print(f"\n  [!] Invalid date: '{date_str}'")
        print("  [!] Expected format: YYYYMMDD (e.g., 19810101)")
        sys.exit(1)

    # Step 2: Serial number
    print()
    print("-" * 65)
    serial_number = input(
        f"  Enter the device serial number (SN)\n"
        f"  [press Enter for '{DEFAULT_SN_ASCII}']: "
    ).strip()

    if not serial_number:
        serial_number = DEFAULT_SN_ASCII
    print(f"  -> SN: {serial_number}")

    # Step 3: AES key (optional)
    print()
    print("-" * 65)
    aes_key = input(
        f"  Enter the AES challenge key\n"
        f"  [press Enter for firmware default '{AES_KEY}']: "
    ).strip()

    if not aes_key:
        aes_key = AES_KEY
    print(f"  -> AES key: {aes_key}")

    # Generate all passwords
    print()
    print("=" * 65)
    print(f"  PASSWORDS FOR Date:{date_str}")
    print("=" * 65)
    print()

    passwords = generate_all_passwords(date_str, serial_number, aes_key)

    current_priority = None
    for i, p in enumerate(passwords, 1):
        if p["priority"] != current_priority:
            current_priority = p["priority"]
            if current_priority <= 2:
                print("  -- SHA-256 Challenge (most likely for MEGACABLE) --")
            elif current_priority <= 4:
                print("  -- MD5 Challenge (older firmwares) --")
            elif current_priority <= 5:
                print("  -- Default Passwords (no challenge mode) --")
            elif current_priority <= 9:
                print("  -- Serial Number Based --")
            elif current_priority <= 10:
                print("  -- HMAC (with AES key) --")
            else:
                print("  -- ISP Customization Variants --")
            print()

        pwd_display = p["password"]
        if len(pwd_display) > 40:
            pwd_display = pwd_display[:37] + "..."

        print(f"  {i:2d}. {pwd_display}")
        print(f"      Method: {p['method']}")
        print(f"      When:   {p['feature']}")
        print()

    # Quick-copy summary
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


def cli_mode(date_str: str, serial_number: str | None,
             aes_key: str | None):
    """Non-interactive mode — output passwords directly."""
    if not validate_date(date_str):
        print(f"Error: '{date_str}' is not a valid YYYYMMDD date.",
              file=sys.stderr)
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
        help=f"Device serial number (default: {DEFAULT_SN_ASCII})",
    )
    parser.add_argument(
        "--key", "-k",
        help=f"AES challenge key (default: {AES_KEY})",
    )

    args = parser.parse_args()

    if args.date:
        cli_mode(args.date,
                 args.sn or DEFAULT_SN_ASCII,
                 args.key or AES_KEY)
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
