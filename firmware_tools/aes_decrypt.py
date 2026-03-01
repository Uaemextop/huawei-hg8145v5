#!/usr/bin/env python3
"""AES decryption for Huawei ONT configuration files (aescrypt2 compatible).

Implements both encryption formats used by Huawei ``aescrypt2``:

**AEST format** (V500 R020+ firmware, ``OS_AescryptDecrypt``)::

    Offset  Size  Description
    0x00     4    version  (0x04)
    0x04     4    flags    (0x01 = encrypted)
    0x08    16    AES-256-CBC IV (random, device-unique)
    0x18     n    AES-256-CBC ciphertext (PKCS#7 padded)
    last 4   4    CRC-32 (Huawei custom, covers header + ciphertext)

    Key: derived from device eFuse OTP → KMC domain key → AES-256.
    Fallback key (when KMC unavailable): ``Df7!ui%s9(lmV1L8``
    padded/truncated to 32 bytes for AES-256.

**Legacy format** (V300 R017/R019 firmware)::

    Offset  Size  Description
    0x00     4    version  (0x01)
    0x04     4    checksum
    0x08     n    AES-128-CBC ciphertext (IV = 0x00*16)

    Key: ``Df7!ui<chip_id>9(lmV1L8`` truncated to 16 bytes.

References:
    - ``decompiled/aescrypt2/hw_ssp_aescrypt.c`` (reconstructed from
      ``libhw_ssp_basic.so`` disassembly, branch
      ``copilot/decompile-firmware-aescrypt2`` of HuaweiFirmwareTool)
    - ``decompiled/aescrypt2/hw_ssp_aescrypt.h`` (AEST header struct)
    - ``decompiled/DECOMPILE_FULL_REPORT.md`` (key derivation chain)

Uses pycryptodome for AES operations.
"""

from __future__ import annotations

import gzip
import io
import logging
import re
import struct
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad as _pad, unpad as _unpad
except ImportError:
    AES = None  # type: ignore[assignment,misc]
    logger.warning("pycryptodome not installed: pip install pycryptodome")

# ---------------------------------------------------------------------------
# AEST header constants (from hw_ssp_aescrypt.h)
# ---------------------------------------------------------------------------
AEST_VERSION = 0x04
AEST_FLAG_ENCRYPTED = 0x01
AEST_HEADER_LEN = 24  # version(4) + flags(4) + IV(16)
AEST_CRC_LEN = 4

# Legacy header (V300 firmware)
LEGACY_VERSION = 0x01
LEGACY_HEADER_LEN = 8  # version(4) + checksum(4)

# ---------------------------------------------------------------------------
# Key material
# ---------------------------------------------------------------------------
# Fallback key template found in libhw_ssp_basic.so:0xa0fbf,
# libhw_swm_dll.so:0x37f68, and aescrypt2:0x3117.
KEY_TEMPLATE = "Df7!ui%s9(lmV1L8"

# Known Huawei chip IDs used in ONT devices
KNOWN_CHIP_IDS = [
    "SD5116H",  # HG8145V5, HG8245H, HG8546M (Hi5116H)
    "SD5115H",  # Older HG8245A/H
    "SD5118",   # Some HG8247H
    "SD5116T",  # Some EG8145V5
    "5116H",    # Alternate naming
    "5115H",    # Alternate naming
]

DEFAULT_IV = b"\x00" * 16


def derive_key(chip_id: str) -> bytes:
    """Derive 16-byte AES-128 key from chip ID (legacy format).

    The key is ``KEY_TEMPLATE % chip_id`` truncated to 16 bytes.

    Args:
        chip_id: Device chip ID (e.g. ``"SD5116H"``).

    Returns:
        16-byte AES-128 key.
    """
    key_str = KEY_TEMPLATE % chip_id
    key_bytes = key_str.encode("ascii")
    if len(key_bytes) > 16:
        key_bytes = key_bytes[:16]
    elif len(key_bytes) < 16:
        key_bytes = key_bytes.ljust(16, b"\x00")
    return key_bytes


def derive_key_aes256(chip_id: str = "") -> bytes:
    """Derive 32-byte AES-256 key (AEST format fallback).

    When KMC is unavailable the firmware falls back to the template
    string padded/truncated to 32 bytes for AES-256-CBC.

    Args:
        chip_id: Optional chip ID; empty string uses bare template.

    Returns:
        32-byte AES-256 key.
    """
    if chip_id:
        key_str = KEY_TEMPLATE % chip_id
    else:
        key_str = KEY_TEMPLATE.replace("%s", "")
    key_bytes = key_str.encode("ascii")
    if len(key_bytes) > 32:
        key_bytes = key_bytes[:32]
    else:
        key_bytes = key_bytes.ljust(32, b"\x00")
    return key_bytes


def decrypt_aes_cbc(
    ciphertext: bytes, key: bytes, iv: bytes = DEFAULT_IV
) -> bytes:
    """Decrypt AES-CBC with PKCS#7 unpadding.

    Supports both AES-128 (16-byte key) and AES-256 (32-byte key).

    Args:
        ciphertext: Encrypted data (must be block-aligned).
        key: 16 or 32-byte AES key.
        iv: 16-byte IV (default: all zeros).

    Returns:
        Decrypted bytes.
    """
    if AES is None:
        raise ImportError("pycryptodome required: pip install pycryptodome")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    try:
        return _unpad(decrypted, AES.block_size)
    except ValueError:
        return decrypted


def _looks_like_xml(data: bytes) -> bool:
    """Heuristic check if data looks like XML.

    Requires actual XML tag structure, not just a leading ``<`` byte.
    """
    if not data:
        return False
    head = data[:512].lstrip(b"\x00\t\r\n \xef\xbb\xbf\xff\xfe")
    if head.startswith(b"<?xml"):
        return True
    return bool(re.match(rb"<[A-Za-z_]\w*[\s/>]", head))


def _maybe_gunzip(data: bytes) -> bytes:
    """Decompress gzip if data has gzip magic."""
    if len(data) >= 2 and data[:2] == b"\x1f\x8b":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                return gz.read()
        except OSError:
            pass
    return data


def parse_aest_header(
    data: bytes,
) -> Optional[Tuple[int, int, bytes, bytes]]:
    """Parse an AEST encrypted file header.

    Returns:
        ``(version, flags, iv, ciphertext)`` or ``None`` if not AEST.
    """
    if len(data) < AEST_HEADER_LEN + 16 + AEST_CRC_LEN:
        return None
    version, flags = struct.unpack_from("<II", data, 0)
    if version == AEST_VERSION and flags == AEST_FLAG_ENCRYPTED:
        iv = data[8:24]
        ciphertext = data[24 : len(data) - AEST_CRC_LEN]
        if len(ciphertext) % 16 != 0:
            return None
        return version, flags, iv, ciphertext
    return None


def parse_legacy_header(
    data: bytes,
) -> Optional[Tuple[int, bytes]]:
    """Parse a legacy (V300) encrypted file header.

    Returns:
        ``(version, ciphertext)`` or ``None`` if not legacy format.
    """
    if len(data) < LEGACY_HEADER_LEN + 16:
        return None
    version = struct.unpack_from("<I", data, 0)[0]
    if version == LEGACY_VERSION:
        ciphertext = data[LEGACY_HEADER_LEN:]
        remainder = len(ciphertext) % 16
        if remainder:
            ciphertext = ciphertext[: len(ciphertext) - remainder]
        if len(ciphertext) >= 16:
            return version, ciphertext
    return None


def decrypt_aest(data: bytes, key: Optional[bytes] = None) -> Optional[bytes]:
    """Decrypt an AEST-format file (AES-256-CBC with embedded IV).

    Tries the supplied key first, then all known fallback keys.

    Args:
        data: Raw encrypted file content.
        key: 32-byte AES-256 key. If ``None``, tries fallback keys.

    Returns:
        Decrypted bytes if successful, ``None`` otherwise.
    """
    parsed = parse_aest_header(data)
    if parsed is None:
        return None
    _version, _flags, iv, ciphertext = parsed

    keys_to_try: list[Tuple[str, bytes]] = []
    if key:
        keys_to_try.append(("supplied", key))
    # Fallback: template with each chip ID, and bare template
    keys_to_try.append(("fallback_bare", derive_key_aes256("")))
    for chip_id in KNOWN_CHIP_IDS:
        keys_to_try.append((chip_id, derive_key_aes256(chip_id)))

    for label, try_key in keys_to_try:
        try:
            decrypted = decrypt_aes_cbc(ciphertext, try_key, iv)
            candidate = _maybe_gunzip(decrypted)
            if _looks_like_xml(candidate):
                logger.debug("AEST decrypted with key=%s", label)
                return candidate
        except Exception:
            pass
    return None


def decrypt_legacy(data: bytes) -> Optional[Tuple[str, bytes]]:
    """Decrypt a legacy-format file (AES-128-CBC, IV=0).

    Tries all known chip IDs.

    Args:
        data: Raw encrypted file content.

    Returns:
        ``(chip_id, decrypted_xml)`` if successful, ``None`` otherwise.
    """
    parsed = parse_legacy_header(data)
    if parsed is None:
        return None
    _version, ciphertext = parsed

    for chip_id in KNOWN_CHIP_IDS:
        try:
            key = derive_key(chip_id)
            decrypted = decrypt_aes_cbc(ciphertext, key)
            candidate = _maybe_gunzip(decrypted)
            if _looks_like_xml(candidate):
                return chip_id, candidate
        except Exception:
            pass
    return None


def decrypt_config(data: bytes, chip_id: str = "SD5116H") -> bytes:
    """Decrypt a Huawei config file, auto-detecting format.

    Tries AEST format first (AES-256-CBC with IV in header),
    then legacy format (AES-128-CBC with chip-ID key).

    Args:
        data: Raw encrypted file content.
        chip_id: Preferred chip ID for legacy fallback.

    Returns:
        Decrypted bytes.
    """
    # Try AEST format (V500 R020+ firmware)
    result = decrypt_aest(data)
    if result is not None:
        return result

    # Try legacy format
    legacy = decrypt_legacy(data)
    if legacy is not None:
        return legacy[1]

    # Last resort: raw AES-128-CBC with specified chip_id, skip 8 header
    key = derive_key(chip_id)
    chunk = data[8:] if len(data) > 24 else data
    remainder = len(chunk) % 16
    if remainder:
        chunk = chunk[: len(chunk) - remainder]
    if len(chunk) >= 16:
        return decrypt_aes_cbc(chunk, key)
    return data


def try_decrypt_all_keys(
    data: bytes,
) -> List[Tuple[str, bytes]]:
    """Try decrypting with all known methods and chip IDs.

    Detects AEST vs legacy format and tries all available keys.

    Args:
        data: Encrypted config file content.

    Returns:
        List of ``(key_label, decrypted_xml)`` for successful attempts.
    """
    results: list[Tuple[str, bytes]] = []

    # Try AEST format (AES-256-CBC)
    aest = decrypt_aest(data)
    if aest is not None:
        results.append(("AEST-256", aest))
        return results

    # Try legacy format (AES-128-CBC)
    legacy = decrypt_legacy(data)
    if legacy is not None:
        results.append((legacy[0], legacy[1]))
        return results

    return results


def is_encrypted(filepath: str) -> bool:
    """Check if a file is encrypted (not plaintext XML).

    Args:
        filepath: Path to the file.

    Returns:
        True if the file appears encrypted.
    """
    with open(filepath, "rb") as f:
        header = f.read(16)
    return not _looks_like_xml(header)
