#!/usr/bin/env python3
"""HWNP firmware parser for Huawei ONT .bin images.

Parses the HWNP header and item table, extracts individual items
(KERNEL, ROOTFS, SIGNINFO, etc.) from the firmware package.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional


HWNP_MAGIC = b"HWNP"


@dataclass
class HwnpItem:
    """A single item from an HWNP firmware package."""

    index: int
    name: str
    path: str
    offset: int
    size: int
    data: bytes = field(repr=False)


@dataclass
class HwnpFirmware:
    """Parsed HWNP firmware with header info and items."""

    magic: str
    header_size: int
    data_start: int
    num_items: int
    items: List[HwnpItem] = field(default_factory=list)
    source_path: str = ""


def parse_hwnp(filepath: str) -> Optional[HwnpFirmware]:
    """Parse an HWNP firmware file and return its structure.

    Args:
        filepath: Path to the .bin firmware file.

    Returns:
        HwnpFirmware with all items, or None if not a valid HWNP file.
    """
    with open(filepath, "rb") as fh:
        data = fh.read()
    if data[:4] != HWNP_MAGIC:
        return None

    header_size = struct.unpack_from("<I", data, 0x08)[0]
    data_start = struct.unpack_from("<I", data, 0x0C)[0]
    num_items = struct.unpack_from("<I", data, 0x14)[0]

    fw = HwnpFirmware(
        magic="HWNP",
        header_size=header_size,
        data_start=data_start,
        num_items=num_items,
        source_path=filepath,
    )

    prev_end = 0
    for i in range(num_items):
        entry_off = 0x234 + i * 0x168
        if entry_off + 0xC8 > data_start:
            break

        name = data[entry_off : entry_off + 16].split(b"\x00")[0].decode(
            "ascii", errors="replace"
        )
        path = data[entry_off + 0x68 : entry_off + 0xC8].split(b"\x00")[0].decode(
            "ascii", errors="replace"
        )
        cum_end = struct.unpack_from("<I", data, entry_off + 0x60)[0]

        item_offset = data_start + prev_end
        item_size = cum_end - prev_end

        item_data = b""
        if item_offset < len(data) and item_size > 0:
            item_data = data[item_offset : item_offset + item_size]

        fw.items.append(
            HwnpItem(
                index=i,
                name=name,
                path=path,
                offset=item_offset,
                size=item_size,
                data=item_data,
            )
        )
        prev_end = cum_end

    return fw


def extract_items(fw: HwnpFirmware, output_dir: str) -> Dict[str, str]:
    """Extract all items from a parsed HWNP firmware to disk.

    Args:
        fw: Parsed HWNP firmware.
        output_dir: Directory to write extracted items.

    Returns:
        Dict mapping item name to output file path.
    """
    os.makedirs(output_dir, exist_ok=True)
    extracted = {}

    for item in fw.items:
        if not item.data:
            continue
        fname = f"{item.name}.bin"
        outpath = os.path.join(output_dir, fname)
        with open(outpath, "wb") as f:
            f.write(item.data)
        extracted[item.name] = outpath

    return extracted
