"""ARM binary analysis module for Huawei ONT firmware.

Uses the Capstone disassembly engine to scan ARM binaries extracted from
Huawei HG8145V5 / EG8145V5 firmware images, looking for embedded
cryptographic keys, credentials, and known crypto constants.
"""

from __future__ import annotations

import argparse
import re
import struct
import sys
from typing import Dict, List

try:
    from capstone import CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, Cs

    _CAPSTONE_AVAILABLE = True
except ImportError:
    _CAPSTONE_AVAILABLE = False

# ---------------------------------------------------------------------------
# Known patterns
# ---------------------------------------------------------------------------

_PEM_HEADERS: List[str] = [
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN CERTIFICATE",
    "BEGIN PUBLIC KEY",
    "BEGIN ENCRYPTED PRIVATE KEY",
]

_KNOWN_AES_KEY = b"Df7!ui%s9(lmV1L8"

_CREDENTIAL_PATTERNS: List[bytes] = [
    b"password=",
    b"passwd=",
    b"user=",
    b"admin",
    b"telecomadmin",
    b"HuaweiHomeGateway",
]

# AES S-box (first 4 bytes)
_AES_SBOX_PREFIX = bytes([0x63, 0x7C, 0x77, 0x7B])
# AES inverse S-box (first 4 bytes)
_AES_INV_SBOX_PREFIX = bytes([0x52, 0x09, 0x6A, 0xD5])
# SHA-256 initial hash value H0 = 0x6a09e667
_SHA256_H0_BE = struct.pack(">I", 0x6A09E667)
_SHA256_H0_LE = struct.pack("<I", 0x6A09E667)
# RSA public exponent 65537
_RSA_E_65537 = struct.pack(">I", 0x00010001)


# ---------------------------------------------------------------------------
# Binary scanning
# ---------------------------------------------------------------------------


def scan_binary_for_keys(data: bytes, filename: str = "") -> List[Dict]:
    """Scan binary data for embedded keys, certificates and credentials.

    Args:
        data: Raw binary content to scan.
        filename: Optional source filename for context.

    Returns:
        List of findings, each a dict with keys *type*, *offset*, *size*,
        *description*, and *data_preview*.
    """
    findings: List[Dict] = []
    label = filename or "<binary>"

    # --- PEM headers ---
    for header in _PEM_HEADERS:
        marker = f"-----{header}-----".encode()
        idx = 0
        while True:
            pos = data.find(marker, idx)
            if pos == -1:
                break
            findings.append({
                "type": "pem_header",
                "offset": pos,
                "size": len(marker),
                "description": f"PEM header '{header}' in {label}",
                "data_preview": data[pos:pos + 60].decode(errors="replace"),
            })
            idx = pos + 1

    # --- DER / ASN.1 sequences (0x30 0x82) ---
    idx = 0
    while True:
        pos = data.find(b"\x30\x82", idx)
        if pos == -1:
            break
        if pos + 4 <= len(data):
            seq_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
            if seq_len >= 256:
                findings.append({
                    "type": "der_sequence",
                    "offset": pos,
                    "size": seq_len + 4,
                    "description": (
                        f"DER/ASN.1 sequence ({seq_len + 4} bytes) "
                        f"in {label} – possible X.509 or PKCS structure"
                    ),
                    "data_preview": data[pos:pos + 16].hex(),
                })
        idx = pos + 1

    # --- Known Huawei AES key ---
    idx = 0
    while True:
        pos = data.find(_KNOWN_AES_KEY, idx)
        if pos == -1:
            break
        findings.append({
            "type": "aes_key",
            "offset": pos,
            "size": len(_KNOWN_AES_KEY),
            "description": (
                f"Known Huawei AES-128 config key in {label}"
            ),
            "data_preview": _KNOWN_AES_KEY.decode(),
        })
        idx = pos + 1

    # --- Credential strings ---
    for pattern in _CREDENTIAL_PATTERNS:
        idx = 0
        while True:
            pos = data.find(pattern, idx)
            if pos == -1:
                break
            end = min(pos + 64, len(data))
            findings.append({
                "type": "credential",
                "offset": pos,
                "size": len(pattern),
                "description": (
                    f"Credential pattern '{pattern.decode(errors='replace')}' "
                    f"in {label}"
                ),
                "data_preview": data[pos:end].decode(errors="replace"),
            })
            idx = pos + 1

    # --- RSA modulus patterns (long hex strings) ---
    try:
        text = data.decode(errors="ignore")
    except Exception:
        text = ""
    for m in re.finditer(r"(?:0x)?([0-9a-fA-F]{64,})", text):
        findings.append({
            "type": "rsa_modulus",
            "offset": m.start(),
            "size": len(m.group(0)),
            "description": f"Possible RSA modulus hex string in {label}",
            "data_preview": m.group(0)[:64] + "...",
        })

    return findings


# ---------------------------------------------------------------------------
# ARM disassembly
# ---------------------------------------------------------------------------


def disassemble_arm_snippet(
    data: bytes,
    offset: int = 0,
    count: int = 20,
) -> List[str]:
    """Disassemble a snippet of ARM (little-endian) machine code.

    Args:
        data: Raw binary containing ARM instructions.
        offset: Byte offset into *data* where disassembly starts.
        count: Maximum number of instructions to decode.

    Returns:
        List of formatted instruction strings
        (``"0x{addr}: {mnemonic} {op_str}"``).
    """
    if not _CAPSTONE_AVAILABLE:
        print(
            "WARNING: capstone is not installed – "
            "disassembly is unavailable. Install with: pip install capstone",
            file=sys.stderr,
        )
        return []

    md = Cs(CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN)
    results: List[str] = []
    for insn in md.disasm(data[offset:], offset, count):
        results.append(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
    return results


# ---------------------------------------------------------------------------
# ELF section parser
# ---------------------------------------------------------------------------


def analyze_elf_sections(data: bytes) -> Dict:
    """Parse basic ELF header fields from an ARM 32-bit binary.

    Args:
        data: Raw ELF file bytes.

    Returns:
        Dict with *valid_elf*, *architecture*, *endianness*,
        *entry_point*, and *num_sections*.
    """
    result: Dict = {
        "valid_elf": False,
        "architecture": "unknown",
        "endianness": "unknown",
        "entry_point": 0,
        "num_sections": 0,
    }

    if len(data) < 52 or data[:4] != b"\x7fELF":
        return result

    result["valid_elf"] = True

    # EI_CLASS (byte 4): 1 = 32-bit, 2 = 64-bit
    ei_class = data[4]
    # EI_DATA (byte 5): 1 = little-endian, 2 = big-endian
    ei_data = data[5]

    endian_char = "<" if ei_data == 1 else ">"
    result["endianness"] = "little-endian" if ei_data == 1 else "big-endian"

    # e_machine at offset 18 (2 bytes)
    e_machine = struct.unpack(f"{endian_char}H", data[18:20])[0]
    _ARCH_MAP = {0x28: "ARM", 0xB7: "AArch64", 0x03: "x86", 0x3E: "x86-64"}
    result["architecture"] = _ARCH_MAP.get(e_machine, f"unknown({e_machine:#x})")

    if ei_class == 1:
        # 32-bit ELF: entry_point at 24 (4 bytes), e_shnum at 48 (2 bytes)
        result["entry_point"] = struct.unpack(
            f"{endian_char}I", data[24:28],
        )[0]
        result["num_sections"] = struct.unpack(
            f"{endian_char}H", data[48:50],
        )[0]
    elif ei_class == 2:
        # 64-bit ELF: entry_point at 24 (8 bytes), e_shnum at 60 (2 bytes)
        result["entry_point"] = struct.unpack(
            f"{endian_char}Q", data[24:32],
        )[0]
        result["num_sections"] = struct.unpack(
            f"{endian_char}H", data[60:62],
        )[0]

    return result


# ---------------------------------------------------------------------------
# Crypto-constant scanner
# ---------------------------------------------------------------------------


def scan_for_crypto_constants(data: bytes) -> List[Dict]:
    """Scan binary data for well-known cryptographic constants.

    Looks for AES S-box / inverse S-box prefixes, SHA-256 initial hash
    values, and the RSA public exponent 65537.

    Args:
        data: Raw binary content.

    Returns:
        List of findings, each a dict with *type*, *offset*, and
        *description*.
    """
    findings: List[Dict] = []

    _patterns: List[tuple] = [
        (_AES_SBOX_PREFIX, "aes_sbox", "AES S-box (first 4 bytes: 63 7c 77 7b)"),
        (_AES_INV_SBOX_PREFIX, "aes_inv_sbox", "AES inverse S-box (first 4 bytes: 52 09 6a d5)"),
        (_SHA256_H0_BE, "sha256_iv", "SHA-256 initial hash value H0 (big-endian)"),
        (_SHA256_H0_LE, "sha256_iv", "SHA-256 initial hash value H0 (little-endian)"),
        (_RSA_E_65537, "rsa_exponent", "RSA public exponent 65537 (0x00010001)"),
    ]

    for needle, kind, description in _patterns:
        idx = 0
        while True:
            pos = data.find(needle, idx)
            if pos == -1:
                break
            findings.append({
                "type": kind,
                "offset": pos,
                "description": f"{description} at offset {pos:#x}",
            })
            idx = pos + 1

    return findings


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def generate_binary_analysis_report(findings: List[Dict]) -> str:
    """Generate a markdown report from scan findings.

    Args:
        findings: Combined list of dicts produced by
            :func:`scan_binary_for_keys` and/or
            :func:`scan_for_crypto_constants`.

    Returns:
        A Markdown-formatted report string.
    """
    lines: List[str] = [
        "# Binary Analysis Report\n",
        f"**Total findings:** {len(findings)}\n",
    ]

    # Group by type
    by_type: Dict[str, List[Dict]] = {}
    for f in findings:
        by_type.setdefault(f["type"], []).append(f)

    for kind, items in by_type.items():
        lines.append(f"## {kind} ({len(items)} hit{'s' if len(items) != 1 else ''})\n")
        lines.append("| Offset | Description | Preview |")
        lines.append("|--------|-------------|---------|")
        for item in items:
            offset = f"0x{item['offset']:x}"
            desc = item.get("description", "")
            preview = item.get("data_preview", item.get("size", ""))
            lines.append(f"| {offset} | {desc} | {preview} |")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Demo helper
# ---------------------------------------------------------------------------


def _build_demo_binary() -> bytes:
    """Create a small synthetic binary with embedded key patterns."""
    parts: List[bytes] = []

    # Padding
    parts.append(b"\x00" * 64)
    # PEM certificate header
    parts.append(b"-----BEGIN CERTIFICATE-----\nMIIBxTCCAW...\n-----END CERTIFICATE-----\n")
    parts.append(b"\x00" * 32)
    # Known Huawei AES key
    parts.append(_KNOWN_AES_KEY)
    parts.append(b"\x00" * 32)
    # DER sequence header with length >= 256
    parts.append(b"\x30\x82\x01\x22")  # sequence, length 290
    parts.append(b"\x00" * 290)
    # Credential patterns
    parts.append(b"password=admin123\x00")
    parts.append(b"user=telecomadmin\x00")
    # AES S-box prefix
    parts.append(_AES_SBOX_PREFIX)
    parts.append(b"\x00" * 16)
    # SHA-256 H0
    parts.append(_SHA256_H0_BE)
    parts.append(b"\x00" * 16)
    # RSA exponent
    parts.append(_RSA_E_65537)
    parts.append(b"\x00" * 32)
    # A couple of ARM NOP instructions (mov r0, r0) for disassembly
    parts.append(b"\x00\x00\xa0\xe1" * 4)

    return b"".join(parts)


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry-point for binary analysis."""
    parser = argparse.ArgumentParser(
        description="Analyze ARM binaries from Huawei firmware for "
        "embedded cryptographic keys and credentials.",
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="Path to a binary file to analyse",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run a demonstration with a synthetic test binary",
    )
    args = parser.parse_args()

    if not args.file and not args.demo:
        parser.print_help()
        return

    if args.demo:
        print("=== Demo mode: analyzing synthetic binary ===\n")
        data = _build_demo_binary()
        filename = "<synthetic demo>"
    else:
        with open(args.file, "rb") as fh:
            data = fh.read()
        filename = args.file

    # Key / credential scan
    key_findings = scan_binary_for_keys(data, filename)

    # Crypto-constant scan
    crypto_findings = scan_for_crypto_constants(data)

    # ELF analysis (only when it looks like an ELF)
    if data[:4] == b"\x7fELF":
        elf_info = analyze_elf_sections(data)
        print("ELF Info:")
        for k, v in elf_info.items():
            print(f"  {k}: {v}")
        print()

    # Disassembly snippet
    if _CAPSTONE_AVAILABLE:
        # Find ARM instructions – in demo they are at the tail
        arm_offset = max(0, len(data) - 16)
        insns = disassemble_arm_snippet(data, offset=arm_offset, count=10)
        if insns:
            print("ARM disassembly snippet:")
            for line in insns:
                print(f"  {line}")
            print()
    else:
        print(
            "WARNING: capstone is not installed – skipping disassembly. "
            "Install with: pip install capstone\n",
            file=sys.stderr,
        )

    # Combined report
    all_findings = key_findings + crypto_findings
    report = generate_binary_analysis_report(all_findings)
    print(report)


if __name__ == "__main__":
    main()
