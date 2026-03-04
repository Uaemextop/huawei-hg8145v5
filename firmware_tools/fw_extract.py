#!/usr/bin/env python3
"""Extract and decrypt hw_*.xml configs from Huawei firmware .bin files.

Full pipeline:

1. Parse HWNP firmware package (using ``HWNPFirmware`` parser logic from
   `HuaweiFirmwareTool <https://github.com/Uaemextop/HuaweiFirmwareTool>`_,
   branch ``copilot/decompile-firmware-aescrypt2``).
2. Extract embedded tar.gz archives (``equipment.tar.gz`` contains plaintext
   ``hw_cli.xml``, ``hw_diag_cli.xml``, ``hw_shell_cli.xml``).
3. Find SquashFS images inside KERNEL/ROOTFS items and extract rootfs.
4. Locate all ``hw_*.xml`` configuration files.
5. Decrypt encrypted configs using both:

   - **AEST format** (AES-256-CBC with IV in header, key from eFuse/KMC,
     fallback ``Df7!ui%s9(lmV1L8``).
   - **Legacy format** (AES-128-CBC, IV=0, chip-ID-derived key).

   Based on decompiled ``aescrypt2`` / ``hw_ssp_aescrypt.c`` from
   ``decompiled/aescrypt2/`` in HuaweiFirmwareTool.

Usage::

    python -m firmware_tools.fw_extract firmware.bin -o output_dir
    python -m firmware_tools.fw_extract --repo /path/to/realfirmware-net -o output_dir
"""

from __future__ import annotations

import argparse
import gzip
import io
import os
import shutil
import sys
import tarfile
from pathlib import Path
from typing import Dict, List, Optional

from firmware_tools.hwnp_parser import HwnpItem, parse_hwnp
from firmware_tools.squashfs_extractor import (
    extract_squashfs,
    find_squashfs,
)
from firmware_tools.aes_decrypt import (
    KNOWN_CHIP_IDS,
    is_encrypted,
    try_decrypt_all_keys,
)


def find_firmware_files(repo_dir: str) -> List[str]:
    """Find all Huawei .bin firmware files in a repository.

    Args:
        repo_dir: Path to firmware repository root.

    Returns:
        List of absolute paths to .bin files > 1MB.
    """
    firmware_files = []
    for root, _dirs, files in os.walk(repo_dir):
        for f in files:
            if f.lower().endswith(".bin"):
                fp = os.path.join(root, f)
                if os.path.getsize(fp) > 1_000_000:
                    firmware_files.append(fp)
    return sorted(firmware_files)


def extract_rootfs_from_firmware(fw_path: str, work_dir: str) -> Optional[str]:
    """Extract rootfs from an HWNP firmware file.

    Parses the HWNP package, extracts KERNEL and ROOTFS items,
    and finds/extracts the SquashFS rootfs.  Falls back to searching
    the entire firmware binary if per-item search fails.

    Args:
        fw_path: Path to firmware .bin file.
        work_dir: Working directory for extraction.

    Returns:
        Path to extracted rootfs directory, or None on failure.
    """
    fw = parse_hwnp(fw_path)
    if fw is None:
        return None

    # Try ROOTFS first, then KERNEL (squashfs is inside both)
    for item in fw.items:
        if item.name in ("ROOTFS", "KERNEL") and item.size > 100_000:
            sqfs_list = find_squashfs(item.data)
            if not sqfs_list:
                continue

            offset, size = sqfs_list[0]
            rootfs_dir = os.path.join(work_dir, "rootfs")
            result = extract_squashfs(item.data, rootfs_dir, offset, size)
            if result:
                return result

    # Fallback: search the entire firmware binary for squashfs
    with open(fw_path, "rb") as fh:
        raw_data = fh.read()
    sqfs_list = find_squashfs(raw_data)
    if sqfs_list:
        offset, size = sqfs_list[0]
        rootfs_dir = os.path.join(work_dir, "rootfs")
        result = extract_squashfs(raw_data, rootfs_dir, offset, size)
        if result:
            return result

    return None


def find_hw_xml_files(rootfs_dir: str) -> Dict[str, str]:
    """Find all hw_*.xml files in an extracted rootfs.

    Args:
        rootfs_dir: Path to extracted rootfs.

    Returns:
        Dict mapping relative path to absolute path.
    """
    hw_files: Dict[str, str] = {}
    for root, _dirs, files in os.walk(rootfs_dir):
        for f in files:
            if f.startswith("hw_") and f.endswith(".xml"):
                fp = os.path.join(root, f)
                rel = os.path.relpath(fp, rootfs_dir)
                hw_files[rel] = fp
    return hw_files


def extract_tar_gz_from_items(fw_path: str, work_dir: str) -> Dict[str, str]:
    """Extract hw_*.xml from tar.gz archives embedded in HWNP items.

    Huawei firmware packages embed ``equipment.tar.gz`` which contains
    plaintext ``hw_cli.xml``, ``hw_diag_cli.xml``, ``hw_shell_cli.xml``
    inside ``equipment/wap/``.

    Args:
        fw_path: Path to firmware .bin file.
        work_dir: Working directory for extraction.

    Returns:
        Dict mapping filename to absolute path of extracted file.
    """
    fw = parse_hwnp(fw_path)
    if fw is None:
        return {}

    extracted: Dict[str, str] = {}
    tar_dir = os.path.join(work_dir, "tars")
    os.makedirs(tar_dir, exist_ok=True)

    for item in fw.items:
        if item.size < 100:
            continue
        # Detect gzip magic in item data
        data = item.data
        if len(data) < 2 or data[:2] != b"\x1f\x8b":
            continue

        try:
            decompressed = gzip.decompress(data)
        except Exception:
            continue

        # Check if it's a tar archive
        if len(decompressed) < 262:
            continue
        if decompressed[257:262] != b"ustar":
            continue

        try:
            tf = tarfile.open(fileobj=io.BytesIO(decompressed))
            for member in tf.getmembers():
                basename = os.path.basename(member.name)
                if basename.startswith("hw_") and basename.endswith(".xml"):
                    f = tf.extractfile(member)
                    if f is None:
                        continue
                    content = f.read()
                    out_path = os.path.join(tar_dir, basename)
                    with open(out_path, "wb") as fout:
                        fout.write(content)
                    extracted[basename] = out_path
            tf.close()
        except (tarfile.TarError, Exception):
            continue

    return extracted


def process_firmware(
    fw_path: str, output_dir: str, work_dir: str
) -> Dict[str, str]:
    """Process a single firmware file: extract rootfs and decrypt configs.

    Extraction sources (in priority order):

    1. **tar.gz items** — ``equipment.tar.gz`` inside HWNP items contains
       plaintext ``hw_cli.xml``, ``hw_diag_cli.xml``, ``hw_shell_cli.xml``.
    2. **SquashFS rootfs** — all ``hw_*.xml`` from ``/etc/wap/``.
       Encrypted files are decrypted using AEST (AES-256-CBC) or legacy
       (AES-128-CBC) format with known fallback keys.

    Args:
        fw_path: Path to firmware .bin file.
        output_dir: Directory for decrypted configs.
        work_dir: Temporary working directory.

    Returns:
        Dict mapping filename to status string.
    """
    results: Dict[str, str] = {}
    fw_name = Path(fw_path).stem.replace(" ", "_")
    fw_out = os.path.join(output_dir, fw_name)
    os.makedirs(fw_out, exist_ok=True)

    # --- Step 1: Extract hw_*.xml from embedded tar.gz archives ---
    tar_files = extract_tar_gz_from_items(fw_path, work_dir)
    if tar_files:
        tar_out = os.path.join(fw_out, "from_tar")
        os.makedirs(tar_out, exist_ok=True)
        for fname, fpath in sorted(tar_files.items()):
            dst = os.path.join(tar_out, fname)
            shutil.copy2(fpath, dst)
            results[f"tar/{fname}"] = "plaintext (from tar.gz)"

    # --- Step 2: Extract rootfs and find hw_*.xml ---
    rootfs = extract_rootfs_from_firmware(fw_path, work_dir)
    if rootfs is None and not tar_files:
        results["_status"] = "no_rootfs"
        return results

    if rootfs:
        hw_files = find_hw_xml_files(rootfs)
        for rel_path, abs_path in sorted(hw_files.items()):
            fname = os.path.basename(abs_path)
            with open(abs_path, "rb") as fh:
                data = fh.read()

            if not is_encrypted(abs_path):
                dst = os.path.join(fw_out, fname)
                shutil.copy2(abs_path, dst)
                results[fname] = "plaintext"
            else:
                # Try decryption with AEST + legacy formats
                decrypted = try_decrypt_all_keys(data)
                if decrypted:
                    key_label, xml_data = decrypted[0]
                    dst = os.path.join(
                        fw_out, fname.replace(".xml", "_decrypted.xml")
                    )
                    with open(dst, "wb") as f:
                        f.write(xml_data)
                    results[fname] = f"decrypted ({key_label})"

                    orig_dst = os.path.join(fw_out, fname)
                    shutil.copy2(abs_path, orig_dst)
                else:
                    dst = os.path.join(fw_out, fname)
                    shutil.copy2(abs_path, dst)
                    results[fname] = "encrypted (eFuse/KMC key required)"

        # Extract key material files
        for key_name in ("aes_string", "kmc_store_A", "kmc_store_B"):
            for root, _dirs, files in os.walk(rootfs):
                for f in files:
                    if f == key_name:
                        src = os.path.join(root, f)
                        keys_dir = os.path.join(fw_out, "keys")
                        os.makedirs(keys_dir, exist_ok=True)
                        dst = os.path.join(keys_dir, f)
                        if not os.path.exists(dst):
                            shutil.copy2(src, dst)

    results["_status"] = "ok"
    return results


def generate_report(
    all_results: Dict[str, Dict[str, str]], output_dir: str
) -> str:
    """Generate a markdown report of extraction results.

    Args:
        all_results: Dict mapping firmware name to file results.
        output_dir: Output directory for the report.

    Returns:
        Report content as string.
    """
    lines = [
        "# Extracted Huawei ONT Firmware Configurations",
        "",
        "Configurations extracted from Huawei ONT firmware images found in",
        "[realfirmware-net](https://github.com/Uaemextop/realfirmware-net).",
        "",
        "Decryption uses AES-128-CBC with chip-ID-derived keys from",
        "[HuaweiFirmwareTool](https://github.com/Uaemextop/HuaweiFirmwareTool).",
        "",
        "## Summary",
        "",
        "| Firmware | Status | Plaintext | Decrypted | Encrypted |",
        "|----------|--------|-----------|-----------|-----------|",
    ]

    for fw_name, results in sorted(all_results.items()):
        status = results.get("_status", "unknown")
        plain = sum(
            1 for v in results.values()
            if v.startswith("plaintext")
        )
        decrypted = sum(1 for v in results.values() if v.startswith("decrypted"))
        encrypted = sum(
            1 for v in results.values() if v.startswith("encrypted")
        )
        lines.append(
            f"| `{fw_name}` | {status} | {plain} | {decrypted} | {encrypted} |"
        )

    lines.extend([
        "",
        "## Encryption Formats",
        "",
        "Based on decompiled `aescrypt2` / `hw_ssp_aescrypt.c` from",
        "[HuaweiFirmwareTool](https://github.com/Uaemextop/HuaweiFirmwareTool)",
        "(branch `copilot/decompile-firmware-aescrypt2`).",
        "",
        "### AEST Format (V500 R020+ firmware)",
        "",
        "```",
        "Offset  Size  Description",
        "0x00     4    version  (0x04)",
        "0x04     4    flags    (0x01 = encrypted)",
        "0x08    16    AES-256-CBC IV (random)",
        "0x18     n    AES-256-CBC ciphertext (PKCS#7 padded)",
        "last 4   4    CRC-32 (Huawei custom)",
        "```",
        "",
        "Key: derived from device eFuse OTP → KMC domain key.",
        "Fallback: `Df7!ui%s9(lmV1L8` padded to 32 bytes.",
        "",
        "### Legacy Format (V300 R017/R019 firmware)",
        "",
        "```",
        "Offset  Size  Description",
        "0x00     4    version  (0x01)",
        "0x04     4    checksum",
        "0x08     n    AES-128-CBC ciphertext (IV = 0x00*16)",
        "```",
        "",
        "Key: `Df7!ui<chip_id>9(lmV1L8` truncated to 16 bytes.",
        "",
        "### Known Chip IDs",
        "",
    ])
    for cid in KNOWN_CHIP_IDS:
        lines.append(f"- `{cid}`")

    lines.extend([
        "",
        "### Plaintext Sources",
        "",
        "`equipment.tar.gz` (embedded in HWNP items) contains plaintext:",
        "- `hw_cli.xml` — CLI command definitions",
        "- `hw_diag_cli.xml` — diagnostic CLI commands",
        "- `hw_shell_cli.xml` — shell CLI commands",
        "",
        "### eFuse Key Required",
        "",
        "Files marked 'eFuse/KMC key required' use device-bound AES-256 keys.",
        "See `keys/HOW_TO_DECRYPT_EFUSE.md` in HuaweiFirmwareTool for extraction.",
    ])

    report = "\n".join(lines) + "\n"
    report_path = os.path.join(output_dir, "EXTRACTED_CONFIGS.md")
    with open(report_path, "w") as f:
        f.write(report)
    return report


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Extract and decrypt hw_*.xml from Huawei HWNP firmware"
    )
    parser.add_argument("firmware", nargs="*", help="Firmware .bin file(s)")
    parser.add_argument(
        "--repo", help="Path to realfirmware-net repository"
    )
    parser.add_argument(
        "-o", "--output", default="extracted_configs", help="Output directory"
    )
    args = parser.parse_args()

    import tempfile

    output_dir = os.path.abspath(args.output)
    os.makedirs(output_dir, exist_ok=True)

    fw_files: list[str] = []
    if args.firmware:
        fw_files = args.firmware
    elif args.repo:
        fw_files = find_firmware_files(args.repo)
    else:
        parser.print_help()
        sys.exit(1)

    print(f"Processing {len(fw_files)} firmware file(s)...")

    all_results: Dict[str, Dict[str, str]] = {}

    for fw_path in fw_files:
        fw_name = Path(fw_path).stem.replace(" ", "_")
        print(f"\n{'=' * 60}")
        print(f"Firmware: {fw_name}")

        with tempfile.TemporaryDirectory(prefix=f"fw_{fw_name}_") as work_dir:
            results = process_firmware(fw_path, output_dir, work_dir)
            all_results[fw_name] = results

            status = results.get("_status", "unknown")
            if status == "ok":
                plain = sum(1 for v in results.values() if v == "plaintext")
                dec = sum(
                    1 for v in results.values() if v.startswith("decrypted")
                )
                enc = sum(
                    1 for v in results.values() if v.startswith("encrypted")
                )
                print(
                    f"  ✓ {plain} plaintext, {dec} decrypted, {enc} encrypted"
                )
            else:
                print(f"  ✗ {status}")

    # Generate report
    generate_report(all_results, output_dir)
    print(f"\nResults saved to {output_dir}/")
    print(f"Report: {output_dir}/EXTRACTED_CONFIGS.md")


if __name__ == "__main__":
    main()
