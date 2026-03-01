#!/usr/bin/env python3
"""SquashFS rootfs extractor for Huawei firmware items.

Locates SquashFS images embedded within HWNP items (KERNEL, ROOTFS)
and extracts them using ``unsquashfs``.
"""

from __future__ import annotations

import os
import struct
import subprocess
import tempfile
from typing import List, Optional, Tuple

SQUASHFS_MAGIC_LE = b"hsqs"
SQUASHFS_MAGIC_BE = b"sqsh"


def find_squashfs(data: bytes) -> List[Tuple[int, int]]:
    """Find all SquashFS images in a binary blob.

    Args:
        data: Raw binary data to search.

    Returns:
        List of (offset, bytes_used) sorted by size descending.
    """
    results: list[Tuple[int, int]] = []
    for magic in (SQUASHFS_MAGIC_LE, SQUASHFS_MAGIC_BE):
        idx = 0
        while True:
            pos = data.find(magic, idx)
            if pos == -1:
                break
            if pos + 48 <= len(data):
                bytes_used = struct.unpack_from("<Q", data, pos + 40)[0]
                if 0 < bytes_used <= len(data) - pos:
                    results.append((pos, bytes_used))
            idx = pos + 1
    results.sort(key=lambda t: t[1], reverse=True)
    return results


def extract_squashfs(
    data: bytes, dest_dir: str, offset: int = 0, size: Optional[int] = None
) -> Optional[str]:
    """Extract a SquashFS image from binary data.

    Args:
        data: Raw binary data containing the SquashFS image.
        dest_dir: Directory to extract the rootfs into.
        offset: Byte offset of the SquashFS image within data.
        size: Size of the SquashFS image (if known).

    Returns:
        Path to extracted rootfs directory, or None on failure.
    """
    sqfs_data = data[offset:]
    if size:
        sqfs_data = data[offset : offset + size]

    with tempfile.NamedTemporaryFile(suffix=".sqfs", delete=False) as tmp:
        tmp.write(sqfs_data)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ["unsquashfs", "-no-xattrs", "-d", dest_dir, "-f", tmp_path],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if os.path.isdir(dest_dir):
            file_count = sum(len(fs) for _, _, fs in os.walk(dest_dir))
            if file_count > 0:
                return dest_dir
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    finally:
        os.unlink(tmp_path)

    return None


def extract_rootfs_from_item(item_data: bytes, output_dir: str) -> Optional[str]:
    """Find and extract the largest SquashFS rootfs from an HWNP item.

    Args:
        item_data: Raw data of a KERNEL or ROOTFS item.
        output_dir: Base directory for extraction.

    Returns:
        Path to extracted rootfs, or None if no SquashFS found.
    """
    squashfs_list = find_squashfs(item_data)
    if not squashfs_list:
        return None

    # Use the largest SquashFS (typically the rootfs)
    offset, size = squashfs_list[0]
    rootfs_dir = os.path.join(output_dir, "rootfs")
    return extract_squashfs(item_data, rootfs_dir, offset, size)
