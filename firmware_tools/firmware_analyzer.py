#!/usr/bin/env python3
"""
Huawei Firmware Analyzer - Extracts keys, certificates, credentials from firmware.

Analyzes firmware files from realfirmware-net repository, extracting:
- PEM/KEY/DER certificates and private keys
- Credentials (usernames/passwords) from config files and documents
- Embedded AES keys from binaries using Capstone disassembly
- Encrypted file detection and analysis

Usage:
    python firmware_tools/firmware_analyzer.py [--source-dir DIR] [--output-dir DIR] [--json FILE]
"""

import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

# ─── Known Huawei firmware keys & credentials ────────────────────────────

# AES-256 key found across multiple Huawei ONT firmware binaries
HUAWEI_AES_KEY = "Df7!ui%s9(lmV1L8"

# RSA-256 su_pub_key (trivially factorable, only 256 bits)
SU_PUB_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAM22zaKqNheaojn8HUjOnoIZTMV3pjGJ
ei31Df0fINrVAgMBAAE=
-----END PUBLIC KEY-----"""

# HWNP firmware magic bytes
HWNP_MAGIC = b"HWNP"
ZTE_MAGIC = b"\x99\x99\x99\x99"

# PEM pattern markers
PEM_PATTERNS = [
    rb"-----BEGIN (RSA )?PRIVATE KEY-----",
    rb"-----BEGIN CERTIFICATE-----",
    rb"-----BEGIN PUBLIC KEY-----",
    rb"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    rb"-----BEGIN EC PRIVATE KEY-----",
    rb"-----BEGIN DSA PRIVATE KEY-----",
]

# DER certificate magic (ASN.1 SEQUENCE)
DER_MAGIC = b"\x30\x82"

# Credential patterns
CREDENTIAL_PATTERNS = [
    re.compile(r"(?:user(?:name)?|usuario)\s*[=:]\s*(.+)", re.IGNORECASE),
    re.compile(r"(?:pass(?:word)?|contraseña|clave)\s*[=:]\s*(.+)", re.IGNORECASE),
    re.compile(r"telecomadmin", re.IGNORECASE),
    re.compile(r"admintelecom", re.IGNORECASE),
    re.compile(r"F0xB734Fr3@j%YEP", re.IGNORECASE),
]

# Known default credentials from firmware analysis
KNOWN_CREDENTIALS = {
    "Huawei-HG8145V5": [
        {"user": "telecomadmin", "pass": "admintelecom", "context": "Super user default"},
        {"user": "root", "pass": "admin", "context": "Telnet/SSH access"},
        {"user": "telecomadmin", "pass": "F0xB734Fr3@j%YEP", "context": "Totalplay super user"},
        {"user": "root", "pass": "adminHW", "context": "Totalplay telnet"},
    ],
    "Huawei-HG8145V5V3": [
        {"user": "root", "pass": "admin", "context": "Telnet access"},
    ],
    "Huawei-HGONTV500": [
        {"user": "CLARO", "pass": "T3L3C0MCL4R0!", "context": "Claro Dominicana ISP user"},
        {"user": "LCDaTOSCOR", "pass": "me@jrUywiqW+LW*W", "context": "Claro super user"},
    ],
    "ATW-662G": [
        {"user": "TELMEX", "pass": "Nm4Pm2Cc3u", "context": "Telmex ISP user"},
        {"user": "admin", "pass": "NuCom", "context": "Default after reset"},
    ],
    "ZTE-F660": [
        {"user": "root", "pass": "admin", "context": "Telnet access via zte_telnet.exe"},
    ],
    "ZTE-F670L": [
        {"user": "admin", "pass": "Web@0063", "context": "Default web interface"},
    ],
    "ZTE-F680": [
        {"user": "admin", "pass": "1pl4n422ZTE2014.!", "context": "Iplan Argentina"},
        {"user": "admin", "pass": "Web@0063", "context": "Default web interface"},
    ],
    "ZTE-F660-Totalplay": [
        {"user": "WBmew6JF", "pass": "zGe8qHTy", "context": "FactoryMode telnet auth"},
    ],
}


def parse_hwnp_header(data):
    """Parse HWNP firmware header and extract metadata."""
    if data[:4] != HWNP_MAGIC:
        return None

    info = {
        "magic": "HWNP",
        "encrypted": True,
    }

    # Extract product IDs from header (offset ~36)
    try:
        pid_region = data[36:256]
        pid_str = pid_region.split(b"\x00")[0].decode("ascii", errors="ignore")
        if "|" in pid_str:
            info["product_ids"] = [p for p in pid_str.split("|") if p.strip()]
    except Exception:
        pass

    return info


def find_pem_blocks(data):
    """Find all PEM-encoded blocks in binary data."""
    results = []
    text = data if isinstance(data, str) else data.decode("ascii", errors="ignore")

    for pattern in [
        r"(-----BEGIN (?:RSA )?PRIVATE KEY-----.*?-----END (?:RSA )?PRIVATE KEY-----)",
        r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
        r"(-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----)",
        r"(-----BEGIN ENCRYPTED PRIVATE KEY-----.*?-----END ENCRYPTED PRIVATE KEY-----)",
        r"(-----BEGIN EC PRIVATE KEY-----.*?-----END EC PRIVATE KEY-----)",
    ]:
        for match in re.finditer(pattern, text, re.DOTALL):
            pem_block = match.group(1)
            offset = match.start()
            # Determine type
            if "PRIVATE KEY" in pem_block:
                pem_type = "private_key"
                if "ENCRYPTED" in pem_block or "Proc-Type: 4,ENCRYPTED" in pem_block:
                    pem_type = "encrypted_private_key"
            elif "CERTIFICATE" in pem_block:
                pem_type = "certificate"
            elif "PUBLIC KEY" in pem_block:
                pem_type = "public_key"
            else:
                pem_type = "unknown"

            results.append({
                "type": pem_type,
                "offset": offset,
                "pem": pem_block,
                "size": len(pem_block),
            })

    return results


def find_der_certificates(data):
    """Find DER-encoded certificates in binary data."""
    results = []
    idx = 0
    while idx < len(data) - 4:
        if data[idx:idx + 2] == DER_MAGIC:
            # ASN.1 SEQUENCE with 2-byte length
            length = struct.unpack(">H", data[idx + 2:idx + 4])[0]
            if 100 < length < 10000:  # Reasonable cert size
                cert_data = data[idx:idx + 4 + length]
                try:
                    cert_hash = hashlib.sha256(cert_data).hexdigest()[:16]
                    results.append({
                        "type": "der_certificate",
                        "offset": idx,
                        "size": 4 + length,
                        "sha256_prefix": cert_hash,
                    })
                except Exception:
                    pass
        idx += 1
        if len(results) > 50:  # Limit
            break
    return results


def analyze_binary_with_capstone(filepath):
    """Use Capstone to disassemble binary and find embedded keys."""
    if not HAS_CAPSTONE:
        return {"error": "capstone not installed"}

    results = {
        "file": os.path.basename(filepath),
        "size": os.path.getsize(filepath),
        "keys_found": [],
        "strings_of_interest": [],
    }

    with open(filepath, "rb") as f:
        data = f.read()

    # Check ELF header
    if data[:4] != b"\x7fELF":
        results["format"] = "not_elf"
        return results

    endian = data[5]  # 1=LE, 2=BE
    machine = struct.unpack("<H" if endian == 1 else ">H", data[18:20])[0]

    if machine == 40:  # ARM
        results["arch"] = "ARM"
        mode = capstone.CS_MODE_ARM
        if endian == 1:
            mode |= capstone.CS_MODE_LITTLE_ENDIAN
        else:
            mode |= capstone.CS_MODE_BIG_ENDIAN
        md = capstone.Cs(capstone.CS_ARCH_ARM, mode)
    elif machine == 8:  # MIPS
        results["arch"] = "MIPS"
        mode = capstone.CS_MODE_MIPS32
        if endian == 1:
            mode |= capstone.CS_MODE_LITTLE_ENDIAN
        else:
            mode |= capstone.CS_MODE_BIG_ENDIAN
        md = capstone.Cs(capstone.CS_ARCH_MIPS, mode)
    else:
        results["arch"] = f"unsupported_{machine}"
        return results

    # Search for the Huawei AES key
    key_bytes = HUAWEI_AES_KEY.encode()
    pos = data.find(key_bytes)
    if pos >= 0:
        results["keys_found"].append({
            "type": "AES-256",
            "key": HUAWEI_AES_KEY,
            "offset": hex(pos),
            "context": "Huawei firmware encryption key",
        })

        # Disassemble around the key reference
        disasm_start = max(0, pos - 64)
        disasm_end = min(len(data), pos + 64)
        chunk = data[disasm_start:disasm_end]
        instructions = []
        for insn in md.disasm(chunk, disasm_start):
            instructions.append(f"0x{insn.address:08x}: {insn.mnemonic}\t{insn.op_str}")
            if len(instructions) >= 10:
                break
        results["key_disassembly"] = instructions

    # Search for other key patterns
    key_patterns = {
        "RSA_PRIVATE": b"PRIVATE KEY",
        "password_ref": b"password",
        "telecomadmin": b"TelecomAdminPassword",
        "aes_decrypt": b"AESDecrypt",
        "aes_encrypt": b"AESEncrypt",
    }

    for name, pattern in key_patterns.items():
        pos = data.find(pattern)
        if pos >= 0:
            # Get surrounding context
            ctx_start = max(0, pos - 20)
            ctx_end = min(len(data), pos + len(pattern) + 40)
            context = data[ctx_start:ctx_end].decode("ascii", errors="replace")
            results["strings_of_interest"].append({
                "pattern": name,
                "offset": hex(pos),
                "context": context.replace("\x00", " ").strip(),
            })

    return results


def scan_firmware_directory(source_dir):
    """Scan a firmware directory for all analyzable files."""
    results = {
        "firmware_files": [],
        "certificates": [],
        "private_keys": [],
        "public_keys": [],
        "credentials": [],
        "encrypted_files": [],
        "capstone_analysis": [],
    }

    source_path = Path(source_dir)
    if not source_path.exists():
        print(f"Source directory not found: {source_dir}")
        return results

    # Scan firmware binaries
    for bin_file in source_path.rglob("*.bin"):
        if not bin_file.is_file() or bin_file.is_symlink():
            continue
        try:
            with open(bin_file, "rb") as f:
                header = f.read(256)
        except (OSError, PermissionError):
            continue

        fw_info = {
            "path": str(bin_file.relative_to(source_path)),
            "size": bin_file.stat().st_size,
        }

        if len(header) < 4:
            continue

        if header[:4] == HWNP_MAGIC:
            fw_info["format"] = "HWNP (Huawei encrypted)"
            hwnp = parse_hwnp_header(header)
            if hwnp:
                fw_info.update(hwnp)
        elif header[:4] == ZTE_MAGIC:
            fw_info["format"] = "ZTE encrypted"
        elif header[:4] == b"Rar!":
            fw_info["format"] = "RAR archive"
        elif header[:4] == b"fwu.":
            fw_info["format"] = "FWU package"
        else:
            fw_info["format"] = f"unknown ({header[:4].hex()})"

        results["firmware_files"].append(fw_info)

    # Scan for .img files
    for img_file in source_path.rglob("*.img"):
        results["firmware_files"].append({
            "path": str(img_file.relative_to(source_path)),
            "size": img_file.stat().st_size,
            "format": "disk image",
        })

    # Scan for PEM/KEY/DER/CRT files
    for ext in ["*.pem", "*.key", "*.crt", "*.cert", "*.der"]:
        for key_file in source_path.rglob(ext):
            with open(key_file, "rb") as f:
                content = f.read()

            pem_blocks = find_pem_blocks(content)
            for block in pem_blocks:
                entry = {
                    "file": str(key_file.relative_to(source_path)),
                    "type": block["type"],
                    "size": block["size"],
                }
                if block["type"] == "certificate":
                    results["certificates"].append(entry)
                elif "private" in block["type"]:
                    results["private_keys"].append(entry)
                elif block["type"] == "public_key":
                    results["public_keys"].append(entry)

    # Scan for su_pub_key files
    for pub_key in source_path.rglob("su_pub_key"):
        with open(pub_key, "rb") as f:
            content = f.read()
        results["public_keys"].append({
            "file": str(pub_key.relative_to(source_path)),
            "type": "rsa_256_public_key",
            "size": len(content),
            "note": "Trivially factorable RSA-256 key",
        })

    # Scan for dropbear keys
    for db_key in source_path.rglob("dropbear_rsa_host_key"):
        results["private_keys"].append({
            "file": str(db_key.relative_to(source_path)),
            "type": "dropbear_rsa_host_key",
            "size": db_key.stat().st_size,
        })

    # Scan for credentials in text/xml/cfg files
    for ext in ["*.txt", "*.xml", "*.cfg", "*.bat", "*.sh", "*.conf"]:
        for text_file in source_path.rglob(ext):
            try:
                with open(text_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue

            for pattern in CREDENTIAL_PATTERNS:
                matches = pattern.findall(content)
                if matches:
                    results["credentials"].append({
                        "file": str(text_file.relative_to(source_path)),
                        "matches": matches[:5],
                    })
                    break

    # Scan for passwd files
    for passwd_file in source_path.rglob("passwd"):
        if passwd_file.is_file():
            try:
                with open(passwd_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                results["credentials"].append({
                    "file": str(passwd_file.relative_to(source_path)),
                    "type": "passwd",
                    "content": content.strip(),
                })
            except Exception:
                pass

    # Scan for encrypted files
    for enc_file in source_path.rglob("encrypt_spec*"):
        results["encrypted_files"].append({
            "file": str(enc_file.relative_to(source_path)),
            "size": enc_file.stat().st_size if enc_file.is_file() else 0,
        })
    for kmc_file in source_path.rglob("kmc_store_*"):
        results["encrypted_files"].append({
            "file": str(kmc_file.relative_to(source_path)),
            "size": kmc_file.stat().st_size if kmc_file.is_file() else 0,
            "note": "KMC key management store",
        })

    # Capstone analysis of binaries
    if HAS_CAPSTONE:
        for so_file in list(source_path.rglob("*.so"))[:20]:
            if so_file.is_symlink() or not so_file.exists():
                continue
            if so_file.stat().st_size > 10000:
                try:
                    analysis = analyze_binary_with_capstone(str(so_file))
                    if analysis.get("keys_found"):
                        results["capstone_analysis"].append(analysis)
                except Exception as e:
                    pass

        # Also analyze key binaries
        for bin_name in ["aescrypt2", "kmc", "app_m", "clid"]:
            for bin_file in source_path.rglob(bin_name):
                try:
                    analysis = analyze_binary_with_capstone(str(bin_file))
                    if analysis.get("keys_found") or analysis.get("strings_of_interest"):
                        results["capstone_analysis"].append(analysis)
                except Exception:
                    pass

    return results


def generate_report(results, output_dir):
    """Generate EXTRACTED_KEYS.md report from analysis results."""
    report_lines = [
        "# Firmware Analysis Report - Extracted Keys, Certificates & Credentials",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Source: Uaemextop/realfirmware-net (branch: copilot/extract-and-organize-compressed-files)",
        "",
        "---",
        "",
        "## Table of Contents",
        "",
        "1. [Firmware Files Analyzed](#firmware-files-analyzed)",
        "2. [Private Keys](#private-keys)",
        "3. [Certificates](#certificates)",
        "4. [Public Keys](#public-keys)",
        "5. [Default Credentials](#default-credentials)",
        "6. [AES Encryption Key](#aes-encryption-key)",
        "7. [Capstone Binary Analysis](#capstone-binary-analysis)",
        "8. [Encrypted Files](#encrypted-files)",
        "",
        "---",
        "",
        "## Firmware Files Analyzed",
        "",
    ]

    # Firmware files table
    report_lines.append("| File | Size | Format |")
    report_lines.append("|------|------|--------|")
    for fw in results.get("firmware_files", []):
        size_mb = fw["size"] / (1024 * 1024)
        report_lines.append(f"| {fw['path']} | {size_mb:.1f} MB | {fw.get('format', 'unknown')} |")

    report_lines.extend(["", "---", "", "## Private Keys", ""])

    # Private keys
    for key in results.get("private_keys", []):
        report_lines.append(f"### {os.path.basename(key['file'])}")
        report_lines.append(f"- **File**: `{key['file']}`")
        report_lines.append(f"- **Type**: {key['type']}")
        report_lines.append(f"- **Size**: {key['size']} bytes")
        if key.get("pem"):
            report_lines.append(f"\n```\n{key['pem']}\n```\n")
        report_lines.append("")

    report_lines.extend(["---", "", "## Certificates", ""])

    for cert in results.get("certificates", []):
        report_lines.append(f"### {os.path.basename(cert['file'])}")
        report_lines.append(f"- **File**: `{cert['file']}`")
        report_lines.append(f"- **Type**: {cert['type']}")
        report_lines.append(f"- **Size**: {cert['size']} bytes")
        report_lines.append("")

    report_lines.extend(["---", "", "## Public Keys", ""])

    for pub in results.get("public_keys", []):
        report_lines.append(f"### {os.path.basename(pub['file'])}")
        report_lines.append(f"- **File**: `{pub['file']}`")
        report_lines.append(f"- **Type**: {pub['type']}")
        if pub.get("note"):
            report_lines.append(f"- **Note**: {pub['note']}")
        report_lines.append("")

    report_lines.extend(["---", "", "## Default Credentials", ""])

    report_lines.append("| Device | User | Password | Context |")
    report_lines.append("|--------|------|----------|---------|")
    for device, creds in KNOWN_CREDENTIALS.items():
        for cred in creds:
            report_lines.append(
                f"| {device} | `{cred['user']}` | `{cred['pass']}` | {cred['context']} |"
            )

    report_lines.extend([
        "",
        "### Credentials Found in Documents",
        "",
    ])

    for cred_entry in results.get("credentials", [])[:30]:
        report_lines.append(f"- **{cred_entry['file']}**")
        if cred_entry.get("type") == "passwd":
            report_lines.append(f"  ```\n  {cred_entry.get('content', '')[:200]}\n  ```")
        report_lines.append("")

    report_lines.extend(["---", "", "## AES Encryption Key", ""])
    report_lines.extend([
        "The following AES-256 key is embedded in multiple firmware binaries across",
        "all Huawei ONT devices (HG8145V5, HG8245H, HG8246M, HG8247H, HGONTV500):",
        "",
        "```",
        f"Key: {HUAWEI_AES_KEY}",
        "Algorithm: AES-256-CBC",
        "Usage: Configuration encryption, firmware component encryption",
        "```",
        "",
        "### Binaries containing the AES key:",
        "",
        "- `bin/aescrypt2` - AES encryption utility",
        "- `lib/libhw_smp_dm_pdt.so` - Device management library",
        "- `lib/libsmp_api.so` - SMP API library",
        "- `lib/libl3_base_api.so` - L3 base API",
        "- `lib/libl2_base.so` - L2 base library",
        "- `lib/libhw_ssp_basic.so` - SSP basic library",
        "- `lib/libl3_ext.so` - L3 extension library",
        "- `lib/libcfg_api.so` - Config API library",
        "- `lib/libhw_voice_sql.so` - Voice SQL library",
        "- `lib/libhw_smp_web_cfg.so` - Web config library",
        "",
        "### RSA-256 su_pub_key (trivially factorable):",
        "",
        "```",
        SU_PUB_KEY_PEM.strip(),
        "```",
        "",
        "This RSA key is only 256 bits, making it trivially factorable.",
        "It is used for super-user authentication across all Huawei ONT firmwares.",
        "",
    ])

    report_lines.extend(["---", "", "## Capstone Binary Analysis", ""])

    for analysis in results.get("capstone_analysis", []):
        report_lines.append(f"### {analysis['file']}")
        report_lines.append(f"- **Architecture**: {analysis.get('arch', 'unknown')}")
        report_lines.append(f"- **Size**: {analysis['size']} bytes")
        if analysis.get("keys_found"):
            for key in analysis["keys_found"]:
                report_lines.append(f"- **Key Found**: {key['type']} at offset {key['offset']}")
                report_lines.append(f"  - Value: `{key['key']}`")
                report_lines.append(f"  - Context: {key['context']}")
        if analysis.get("strings_of_interest"):
            report_lines.append("- **Strings of interest**:")
            for s in analysis["strings_of_interest"]:
                report_lines.append(f"  - `{s['pattern']}` at {s['offset']}")
        if analysis.get("key_disassembly"):
            report_lines.append("- **Disassembly around key**:")
            report_lines.append("  ```asm")
            for line in analysis["key_disassembly"]:
                report_lines.append(f"  {line}")
            report_lines.append("  ```")
        report_lines.append("")

    report_lines.extend(["---", "", "## Encrypted Files", ""])

    report_lines.extend([
        "### HWNP Encrypted Firmware",
        "",
        "All Huawei `.bin` firmware files use the HWNP format, which includes:",
        "- HWNP header with product IDs and version info",
        "- Encrypted firmware payload",
        "- Contains: Linux kernel (uImage), Squashfs root filesystem, device trees",
        "",
        "### Private Key Encryption",
        "",
        "- `prvt.key` - AES-256-CBC encrypted RSA private key (needs HW passphrase)",
        "- `plugprvt.key` - AES-256-CBC encrypted RSA plugin private key",
        "- `prvt_1_telmex.pem` - AES-256-CBC encrypted (Telmex ISP key)",
        "- `prvt_1_totalplay.pem` - DES-EDE3-CBC encrypted (Totalplay ISP key, weaker)",
        "",
        "### KMC Key Management",
        "",
        "- `encrypt_spec.tar.gz` - Encrypted specification archive",
        "- `kmc_store_A` / `kmc_store_B` - KMC 3.0.0 key management stores (2592 bytes)",
        "- Located at `/etc/wap/kmc_store_A` and `/mnt/jffs2/kmc_store_A`",
        "",
    ])

    for enc in results.get("encrypted_files", []):
        report_lines.append(f"- `{enc['file']}` ({enc.get('size', 0)} bytes)")
        if enc.get("note"):
            report_lines.append(f"  - {enc['note']}")

    report_lines.extend([
        "",
        "---",
        "",
        "## Firmware Decompilation Summary",
        "",
        "### Successfully Decompiled Firmware:",
        "",
        "| Firmware | Kernel | Filesystem | Architecture |",
        "|----------|--------|------------|-------------|",
        "| HG8145V5-.bin (50MB) | Linux 4.4.219 | Squashfs 4.0 | ARM LE |",
        "| HGONTV500.bin (48MB) | Linux 4.4.197 | Squashfs 4.0 | ARM LE |",
        "| HG8247H UPGRADE.bin (27MB) | Linux 3.10.53-HULK2 | Squashfs 4.0 | ARM LE |",
        "| HG8246M TO V5.bin (30MB) | Linux 3.10.53-HULK2 | Squashfs 4.0 | ARM LE |",
        "| ATW-662G rootfs (12MB) | N/A | Squashfs 4.0 xz | ARM LE |",
        "| General rootfs (10MB) | N/A | Squashfs 4.0 xz | ARM LE |",
        "| NuCom-NC8700AC rootfs (8MB) | N/A | Squashfs 4.0 xz | ARM LE |",
        "",
        "### Extraction Method:",
        "",
        "1. HWNP firmware → binwalk extraction → uImage (kernel) + Squashfs (rootfs)",
        "2. Squashfs → unsquashfs → full filesystem with keys, certs, binaries",
        "3. Binaries → Capstone ARM disassembly → embedded key extraction",
        "4. ZTE firmware (0x99999999 magic) → encrypted, requires ZTE-specific tooling",
        "",
    ])

    # Write report
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    report_file = output_path / "EXTRACTED_KEYS.md"
    with open(report_file, "w") as f:
        f.write("\n".join(report_lines))

    return str(report_file)


def copy_key_files(source_dir, output_dir):
    """Copy extracted key/cert files to output directory."""
    source_path = Path(source_dir)
    output_path = Path(output_dir)

    keys_dir = output_path / "keys"
    certs_dir = output_path / "certs"
    keys_dir.mkdir(parents=True, exist_ok=True)
    certs_dir.mkdir(parents=True, exist_ok=True)

    copied = []

    for pattern in ["**/*.pem", "**/*.key", "**/*.crt"]:
        for src_file in source_path.rglob(pattern.replace("**/", "")):
            if src_file.is_file():
                # Determine destination based on type
                with open(src_file, "rb") as f:
                    content = f.read(100)

                basename = src_file.name
                # Add parent dir prefix to avoid name collisions
                parts = src_file.relative_to(source_path).parts
                if len(parts) > 1:
                    prefix = "_".join(parts[:-1]).replace(" ", "_")
                    dest_name = f"{prefix}_{basename}"
                else:
                    dest_name = basename

                if b"PRIVATE KEY" in content:
                    dest = keys_dir / dest_name
                else:
                    dest = certs_dir / dest_name

                try:
                    import shutil
                    shutil.copy2(str(src_file), str(dest))
                    copied.append(str(dest.relative_to(output_path)))
                except Exception as e:
                    print(f"  Warning: Could not copy {src_file}: {e}")

    # Also copy su_pub_key and dropbear keys
    for pattern in ["su_pub_key", "dropbear_rsa_host_key"]:
        for src_file in source_path.rglob(pattern):
            if src_file.is_file():
                parts = src_file.relative_to(source_path).parts
                prefix = "_".join(parts[:-1]).replace(" ", "_")
                dest_name = f"{prefix}_{pattern}"
                dest = keys_dir / dest_name
                try:
                    import shutil
                    shutil.copy2(str(src_file), str(dest))
                    copied.append(str(dest.relative_to(output_path)))
                except Exception:
                    pass

    return copied


def main():
    parser = argparse.ArgumentParser(description="Huawei Firmware Analyzer")
    parser.add_argument("--source-dir", default="/tmp/realfirmware-net/firmware-extracted",
                        help="Source directory with firmware files")
    parser.add_argument("--output-dir", default="firmware_analysis",
                        help="Output directory for extracted keys and report")
    parser.add_argument("--json", default=None,
                        help="Output JSON file with full analysis results")
    parser.add_argument("--scan-rootfs", default=None,
                        help="Additional rootfs directory to scan")
    args = parser.parse_args()

    print(f"Huawei Firmware Analyzer")
    print(f"========================")
    print(f"Source: {args.source_dir}")
    print(f"Output: {args.output_dir}")
    print(f"Capstone: {'available' if HAS_CAPSTONE else 'NOT available'}")
    print()

    # Scan firmware directory
    print("Scanning firmware directory...")
    results = scan_firmware_directory(args.source_dir)

    # Also scan extracted rootfs if available
    rootfs_dirs = [
        "/tmp/fw_extracted/HG8145V5_General/_HG8145V5-.bin.extracted/squashfs-root",
        "/tmp/fw_extracted/HGONTV500/_HGONTV500.bin.extracted/squashfs-root",
        "/tmp/fw_extracted/HG8247H/_HG8247H UPGRADE.bin.extracted/squashfs-root",
        "/tmp/fw_extracted/HG8246M/_Firmware HG8246M TO V5.bin.extracted/squashfs-root",
        "/tmp/fw_extracted/rootfs_ATW662G",
        "/tmp/fw_extracted/rootfs_General",
        "/tmp/fw_extracted/rootfs_NuCom",
    ]

    if args.scan_rootfs:
        rootfs_dirs.append(args.scan_rootfs)

    for rootfs_dir in rootfs_dirs:
        if os.path.isdir(rootfs_dir):
            print(f"  Scanning rootfs: {rootfs_dir}")
            rootfs_results = scan_firmware_directory(rootfs_dir)
            # Merge results
            for key in ["certificates", "private_keys", "public_keys",
                         "credentials", "encrypted_files", "capstone_analysis"]:
                results[key].extend(rootfs_results.get(key, []))

    # Add known credentials
    results["known_credentials"] = KNOWN_CREDENTIALS

    # Copy key files to output directory
    print("\nCopying key files...")
    for rootfs_dir in rootfs_dirs:
        if os.path.isdir(rootfs_dir):
            copied = copy_key_files(rootfs_dir, args.output_dir)
            for c in copied:
                print(f"  Copied: {c}")

    # Generate report
    print("\nGenerating report...")
    report_file = generate_report(results, args.output_dir)
    print(f"Report written to: {report_file}")

    # Write JSON output
    if args.json:
        json_path = os.path.join(args.output_dir, args.json)
        with open(json_path, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"JSON output written to: {json_path}")

    # Summary
    print(f"\nSummary:")
    print(f"  Firmware files: {len(results['firmware_files'])}")
    print(f"  Private keys: {len(results['private_keys'])}")
    print(f"  Certificates: {len(results['certificates'])}")
    print(f"  Public keys: {len(results['public_keys'])}")
    print(f"  Credential sources: {len(results['credentials'])}")
    print(f"  Encrypted files: {len(results['encrypted_files'])}")
    print(f"  Capstone analyses: {len(results['capstone_analysis'])}")


if __name__ == "__main__":
    main()
