"""Comprehensive Huawei ONT firmware analysis module.

Catalogs keys, certificates, credentials, and encryption artifacts
found across Huawei HG8145V5 / EG8145V5 / HN8145XR firmware images.
"""

from __future__ import annotations

import argparse
import textwrap
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Firmware repositories analysed
# ---------------------------------------------------------------------------

FIRMWARE_REPOS: List[str] = [
    "firmware-EG8145V5-V500R022C00SPC340B019",
    "firmware-HG8145V5-V500R020C10SPC212",
    "firmware-HG8145C-V5R019C00S105",
    "firmware-HN8145XR-V500R022C10SPC160",
    "firmware-HG8245C-8145C-BLUE-R019-xpon",
    "firmware-HG8145C_17120_ENG",
    "firmware-HG8145V5-V500R020C10SPC212_1",
    "firmware-EG8145V5-V500R022C00SPC340B019_1",
    "firmware-HN8145XR-V500R022C10SPC160_1",
    "firmware-HG8145C-V5R019C00S105_1",
    "firmware-HG8245C-8145C-BLUE-R019-xpon_1",
    "firmware-HG8145C_17120_ENG_1",
]

# ---------------------------------------------------------------------------
# Huawei devices from realfirmware.net extract branch
# ---------------------------------------------------------------------------

REALFIRMWARE_NET_DEVICES: List[str] = [
    "Huawei-EG8141A5",
    "Huawei-EG8145V5",
    "Huawei-EG8240H5",
    "Huawei-EG8245H5",
    "Huawei-HG8145Q2",
    "Huawei-HG8145V5",
    "Huawei-HG8145V5V3",
    "Huawei-HG8145X6",
    "Huawei-HG8145X6-10",
    "Huawei-HG8145X7B",
    "Huawei-HG8245",
    "Huawei-HG8245A",
    "Huawei-HG8245H",
    "Huawei-HG8245H5",
    "Huawei-HG8245Q",
    "Huawei-HG8245W5",
    "Huawei-HG8245W5-6T",
    "Huawei-HG8246M",
    "Huawei-HG8247H",
    "Huawei-HG8247H5",
    "Huawei-HGONTV500",
    "Huawei-HS8545M5",
]

# ---------------------------------------------------------------------------
# X.509 Certificates
# ---------------------------------------------------------------------------

CERTIFICATES: Dict[str, str] = {
    "etc/wap/root.crt": (
        "Huawei Equipment CA -> Fixed Network Product CA (2016-2041), "
        "SHA256WithRSA, 4096-bit issuer, 2048-bit subject"
    ),
    "etc/wap/pub.crt": (
        "ont.huawei.com certificate (2020-2030), SHA256WithRSA, 2048-bit, "
        "issued by Fixed Network Product CA"
    ),
    "etc/wap/plugroot.crt": (
        "HuaWei ONT CA self-signed root (2016-2026), SHA256WithRSA, 2048-bit, "
        "email=support@huawei.com"
    ),
    "etc/wap/plugpub.crt": (
        "Plugin signing cert for ont.huawei.com (2017-2067), SHA256WithRSA, "
        "2048-bit, issued by HuaWei ONT CA"
    ),
    "etc/app_cert.crt": (
        "Huawei Root CA DER format (2015-2050), binary DER encoded"
    ),
    "etc/hilinkcert/root.pem": (
        "root.home self-signed certificate (2014-2024, EXPIRED)"
    ),
}

# ---------------------------------------------------------------------------
# Private / public keys
# ---------------------------------------------------------------------------

PRIVATE_KEYS: Dict[str, Dict[str, str]] = {
    "configs/prvt.key": {
        "description": "RSA private key",
        "encryption": "AES-256-CBC",
        "dek_info": "AES-256-CBC,7EC546FB34CA7CD5599763D8D9AE6AC9",
        "notes": "Needs Huawei hardware passphrase to decrypt",
    },
    "configs/plugprvt.key": {
        "description": "RSA private key for plugin signing",
        "encryption": "AES-256-CBC",
        "dek_info": "AES-256-CBC,8699C0FB1C5FA5FF6A3082AFD6082004",
        "notes": "Needs Huawei hardware passphrase to decrypt",
    },
    "configs/su_pub_key": {
        "description": "RSA-256 bit PUBLIC key (trivially factorable)",
        "encryption": "none",
        "modulus_hex": (
            "0xcdb6cdaa"
            "1f20dad5"
        ),
        "exponent": "65537",
        "notes": (
            "Only 256 bits - CRITICALLY WEAK. "
            "Can be factored by any modern computer in seconds."
        ),
    },
    "configs/dropbear_rsa_host_key": {
        "description": "Dropbear SSH host key",
        "encryption": "none (binary format)",
        "notes": "Binary dropbear key format, shared across devices",
    },
}

# ---------------------------------------------------------------------------
# Encryption keys found in firmware binaries
# ---------------------------------------------------------------------------

ENCRYPTION_KEYS: Dict[str, Dict[str, Any]] = {
    "aes_config_key": {
        "value": "Df7!ui%s9(lmV1L8",
        "length_bytes": 16,
        "algorithm": "AES-128",
        "purpose": "Config file encryption/decryption",
        "binary_hits": "5-18 binaries per firmware image",
        "scope": "IDENTICAL across ALL Huawei ONT firmware versions (V300-V500)",
        "binaries": [
            "aescrypt2",
            "hw_s_cltcfg",
            "hw_ssp",
            "cfgtool",
        ],
    },
    "su_pub_key_modulus": {
        "value": "0xcdb6cdaa...1f20dad5",
        "algorithm": "RSA-256",
        "purpose": "Firmware signature verification",
        "notes": "Trivially factorable by any modern computer",
    },
}

# ---------------------------------------------------------------------------
# Service accounts found in etc/wap/passwd
# ---------------------------------------------------------------------------

FIRMWARE_CREDENTIALS: Dict[str, Dict[str, Any]] = {
    "EG8145V5 (V500R022)": {
        "root": {"password_field": "*", "shell": "nologin"},
        "services": [
            "srv_amp", "srv_web", "osgi_proxy", "srv_igmp",
            "cfg_cwmp", "srv_ssmp", "cfg_cli", "srv_bbsp",
            "srv_dbus", "srv_udm", "srv_apm", "srv_kmc",
            "srv_cms", "srv_mu", "srv_em", "srv_clid",
            "srv_comm", "srv_voice", "srv_appm", "srv_cagent",
            "nobody",
        ],
    },
    "HG8145C (V5R019)": {
        "root": {"password_field": "x", "shell": "sh"},
        "osgi": {"password_field": "x", "shell": "sh"},
        "web": {"password_field": "x", "shell": "false"},
        "cli": {"password_field": "x", "shell": "false"},
        "services": [
            "srv_usb", "srv_samba", "srv_amp", "srv_web",
            "osgi_proxy", "srv_igmp", "cfg_cwmp", "srv_ssmp",
            "cfg_omci", "cfg_cli", "cfg_oam", "srv_bbsp",
            "srv_ethoam", "srv_dbus", "srv_wifi", "tool_mu",
            "srv_snmp", "srv_apm", "tool_iac", "nobody",
            "srv_ldsp", "srv_voice", "srv_appm", "srv_user",
        ],
    },
}

# ---------------------------------------------------------------------------
# Default credentials (factory / common ISP defaults)
# ---------------------------------------------------------------------------

DEFAULT_CREDENTIALS: List[Dict[str, str]] = [
    {
        "user": "root",
        "password": "admin or adminHW",
        "service": "Web UI / Telnet",
        "source": "Default factory config",
    },
    {
        "user": "telecomadmin",
        "password": "admintelecom",
        "service": "ISP admin panel",
        "source": "Common ISP default",
    },
    {
        "user": "root",
        "password": "root",
        "service": "Dropbear SSH",
        "source": "Some firmware versions",
    },
    {
        "user": "hw",
        "password": "hw",
        "service": "Telnet diagnostic",
        "source": "Hardware diagnostic mode",
    },
]

# ---------------------------------------------------------------------------
# ISP ACS (Auto-Configuration Server) credentials
# ---------------------------------------------------------------------------

ISP_ACS_CREDENTIALS: List[Dict[str, str]] = [
    {
        "isp": "Telmex",
        "acs_url": "https://acsvip.megared.net.mx",
        "realm": "HuaweiHomeGateway",
        "auth": "HTTP Digest",
    },
    {
        "isp": "Megacable",
        "acs_url": "https://acsvip.megared.net.mx",
        "realm": "HuaweiHomeGateway",
        "auth": "HTTP Digest",
    },
    {
        "isp": "Totalplay",
        "acs_url": "varies by config",
        "realm": "HuaweiHomeGateway",
        "auth": "HTTP Digest",
    },
    {
        "isp": "Claro",
        "acs_url": "varies by country",
        "realm": "HuaweiHomeGateway",
        "auth": "HTTP Digest",
    },
]

# ---------------------------------------------------------------------------
# Encrypted files found in firmware images
# ---------------------------------------------------------------------------

ENCRYPTED_FILES: Dict[str, str] = {
    "configs/encrypt_spec_key.tar.gz": (
        "Encrypted tar.gz, likely AES encrypted with hardware-derived key"
    ),
    "configs/prvt.key": (
        "AES-256-CBC encrypted RSA private key"
    ),
    "configs/plugprvt.key": (
        "AES-256-CBC encrypted RSA private key "
        "(HG8145C uses DES-EDE3-CBC instead - weaker)"
    ),
    "configs/dropbear_rsa_host_key": (
        "Binary dropbear key format"
    ),
    "etc/wap/kmc_store_A": (
        "KMC (Key Management Center) keystore, 2592 bytes, "
        "only present in 5611 firmware"
    ),
}

# ---------------------------------------------------------------------------
# Binary analysis highlights (Capstone / string analysis)
# ---------------------------------------------------------------------------

BINARY_ANALYSIS: Dict[str, Any] = {
    "aes_key_presence": (
        'AES key "Df7!ui%s9(lmV1L8" found as string literal '
        "in multiple ARM LE (little-endian) binaries"
    ),
    "tr069_cwmp": {
        "user_agent": "HuaweiHomeGateway",
        "auth": "HTTP Digest",
        "realm": "HuaweiHomeGateway",
    },
    "user_agents": {
        "bulk_data": "HW-FTTH",
        "mac_report": "HW_IPMAC_REPORT",
        "web_market": "MSIE 9.0",
        "http_client": "MSIE 8.0",
    },
    "key_functions": [
        "ATP_NET_HttpClientCreate",
        "HttpBuildPacketHeader",
        "HttpClientConnectTo",
        "DOWNLOAD_StartDownloadData",
    ],
    "encryption_tooling": (
        "aescrypt2 tool uses KMC for key management (KMC v3.0.0.B003)"
    ),
}


# ===================================================================
# Report generation
# ===================================================================


def generate_report() -> str:
    """Return a comprehensive markdown report of all firmware findings."""
    sections: List[str] = []

    # Header
    sections.append(
        "# Huawei ONT Firmware Analysis Report\n\n"
        "Consolidated findings from analysis of Huawei HG8145V5, EG8145V5, "
        "HG8145C, HN8145XR, and related ONT firmware images.\n"
    )

    # Firmware repos
    sections.append("## Firmware Repositories Analysed\n")
    for repo in FIRMWARE_REPOS:
        sections.append(f"- `{repo}`")
    sections.append("")

    # Devices
    sections.append("## Devices (realfirmware.net)\n")
    for dev in REALFIRMWARE_NET_DEVICES:
        sections.append(f"- {dev}")
    sections.append("")

    # Certificates
    sections.append("## X.509 Certificates\n")
    sections.append("| Path | Description |")
    sections.append("|------|-------------|")
    for path, desc in CERTIFICATES.items():
        sections.append(f"| `{path}` | {desc} |")
    sections.append("")

    # Private keys
    sections.append("## Private / Public Keys\n")
    for path, info in PRIVATE_KEYS.items():
        sections.append(f"### `{path}`\n")
        for key, val in info.items():
            sections.append(f"- **{key}**: {val}")
        sections.append("")

    # Encryption keys
    sections.append("## Encryption Keys in Binaries\n")
    for name, info in ENCRYPTION_KEYS.items():
        sections.append(f"### {name}\n")
        for key, val in info.items():
            if isinstance(val, list):
                sections.append(f"- **{key}**: {', '.join(val)}")
            else:
                sections.append(f"- **{key}**: {val}")
        sections.append("")

    # Service accounts
    sections.append("## Firmware Service Accounts (etc/wap/passwd)\n")
    for fw, info in FIRMWARE_CREDENTIALS.items():
        sections.append(f"### {fw}\n")
        for key, val in info.items():
            if key == "services":
                sections.append(f"- **services**: {', '.join(val)}")
            else:
                sections.append(f"- **{key}**: {val}")
        sections.append("")

    # Default credentials
    sections.append("## Default Credentials\n")
    sections.append("| User | Password | Service | Source |")
    sections.append("|------|----------|---------|--------|")
    for cred in DEFAULT_CREDENTIALS:
        sections.append(
            f"| `{cred['user']}` | `{cred['password']}` "
            f"| {cred['service']} | {cred['source']} |"
        )
    sections.append("")

    # ISP ACS
    sections.append("## ISP ACS Credentials\n")
    sections.append("| ISP | ACS URL | Realm | Auth |")
    sections.append("|-----|---------|-------|------|")
    for acs in ISP_ACS_CREDENTIALS:
        sections.append(
            f"| {acs['isp']} | `{acs['acs_url']}` "
            f"| {acs['realm']} | {acs['auth']} |"
        )
    sections.append("")

    # Encrypted files
    sections.append("## Encrypted Files\n")
    sections.append("| Path | Description |")
    sections.append("|------|-------------|")
    for path, desc in ENCRYPTED_FILES.items():
        sections.append(f"| `{path}` | {desc} |")
    sections.append("")

    # Binary analysis
    sections.append("## Binary Analysis Highlights\n")
    sections.append(f"- {BINARY_ANALYSIS['aes_key_presence']}")
    tr069 = BINARY_ANALYSIS["tr069_cwmp"]
    sections.append(
        f"- TR-069 CWMP: User-Agent=`{tr069['user_agent']}`, "
        f"realm=`{tr069['realm']}`, auth={tr069['auth']}"
    )
    uas = BINARY_ANALYSIS["user_agents"]
    sections.append(
        f"- Other User-Agents: {', '.join(f'{k}=`{v}`' for k, v in uas.items())}"
    )
    sections.append(
        f"- Key functions: {', '.join(f'`{f}`' for f in BINARY_ANALYSIS['key_functions'])}"
    )
    sections.append(f"- {BINARY_ANALYSIS['encryption_tooling']}")
    sections.append("")

    return "\n".join(sections)


def get_all_keys_document() -> str:
    """Return a formatted text document of all private keys and their details."""
    lines: List[str] = []

    lines.append("=" * 72)
    lines.append("  HUAWEI ONT FIRMWARE - KEYS & CERTIFICATES INVENTORY")
    lines.append("=" * 72)
    lines.append("")

    # Certificates
    lines.append("-" * 72)
    lines.append("  CERTIFICATES")
    lines.append("-" * 72)
    for path, desc in CERTIFICATES.items():
        lines.append(f"\n  Path : {path}")
        lines.append(f"  Info : {desc}")
    lines.append("")

    # Private / public keys
    lines.append("-" * 72)
    lines.append("  PRIVATE / PUBLIC KEYS")
    lines.append("-" * 72)
    for path, info in PRIVATE_KEYS.items():
        lines.append(f"\n  Path : {path}")
        for key, val in info.items():
            label = key.replace("_", " ").title()
            lines.append(f"  {label:16s}: {val}")
    lines.append("")

    # Encryption keys
    lines.append("-" * 72)
    lines.append("  ENCRYPTION KEYS (embedded in binaries)")
    lines.append("-" * 72)
    for name, info in ENCRYPTION_KEYS.items():
        lines.append(f"\n  Name : {name}")
        for key, val in info.items():
            label = key.replace("_", " ").title()
            if isinstance(val, list):
                lines.append(f"  {label:16s}: {', '.join(val)}")
            else:
                lines.append(f"  {label:16s}: {val}")
    lines.append("")

    # Encrypted files
    lines.append("-" * 72)
    lines.append("  ENCRYPTED FILES")
    lines.append("-" * 72)
    for path, desc in ENCRYPTED_FILES.items():
        lines.append(f"\n  Path : {path}")
        lines.append(f"  Info : {desc}")
    lines.append("")

    lines.append("=" * 72)
    lines.append("  NOTE: No raw PEM private key material is included.")
    lines.append("  Refer to the firmware paths above to locate the actual")
    lines.append("  key files within extracted firmware images.")
    lines.append("=" * 72)

    return "\n".join(lines)


# ===================================================================
# CLI entry-point
# ===================================================================


def main() -> None:
    """CLI entry-point for firmware analysis reports."""
    parser = argparse.ArgumentParser(
        description="Huawei ONT firmware analysis report generator",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Print comprehensive markdown report",
    )
    parser.add_argument(
        "--keys",
        action="store_true",
        help="Print keys and certificates inventory document",
    )
    args = parser.parse_args()

    if not (args.report or args.keys):
        parser.print_help()
        return

    if args.report:
        print(generate_report())
    if args.keys:
        print(get_all_keys_document())


if __name__ == "__main__":
    main()
