"""
ROM / Firmware Comparison Tool
==============================
Downloads two firmware archives (ZIP, tar.gz, or raw binaries) from local
paths or URLs and produces a human-readable diff report:

* Files only in A or only in B
* Files present in both but different (size + SHA-256)
* Files identical in both

Usage::

    python -m firmware_tools fileA.zip fileB.zip
    python -m firmware_tools https://host/rom1.zip https://host/rom2.zip
    python -m firmware_tools rom1.zip https://host/rom2.zip --output report.txt
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import TextIO
from urllib.parse import urlparse

import requests


# ── helpers ─────────────────────────────────────────────────────────


def is_url(path: str) -> bool:
    """Return ``True`` if *path* looks like an HTTP(S) URL."""
    return path.startswith(("http://", "https://"))


def download_file(url: str, dest_dir: Path, timeout: int = 120) -> Path:
    """Download *url* into *dest_dir*, returning the local path.

    Streams the response to avoid loading the entire file in memory.
    Uses the filename from the URL (or ``Content-Disposition`` header)
    and falls back to ``firmware.bin`` when neither is available.
    """
    print(f"  ↓ Downloading {url[:120]}…")
    resp = requests.get(url, stream=True, timeout=timeout, allow_redirects=True)
    resp.raise_for_status()

    # Resolve filename from Content-Disposition or URL path
    cd = resp.headers.get("Content-Disposition", "")
    if "filename=" in cd:
        fname = cd.split("filename=")[-1].strip().strip("\"'")
    else:
        fname = os.path.basename(urlparse(url).path) or "firmware.bin"

    dest = dest_dir / fname
    written = 0
    with dest.open("wb") as fh:
        for chunk in resp.iter_content(chunk_size=1 << 20):
            fh.write(chunk)
            written += len(chunk)
    size_mb = written / (1 << 20)
    print(f"  ✓ Saved {dest.name} ({size_mb:.1f} MB)")
    return dest


def sha256_file(path: Path, buf_size: int = 1 << 20) -> str:
    """Return the hex SHA-256 digest of *path*."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            data = fh.read(buf_size)
            if not data:
                break
            h.update(data)
    return h.hexdigest()


def extract_archive(archive: Path, dest: Path) -> Path:
    """Extract a ZIP or tar archive into *dest* and return the extraction root.

    If the archive contains a single top-level directory, that directory
    is returned.  Otherwise *dest* itself is returned.
    """
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive, "r") as zf:
            zf.extractall(dest)
    elif tarfile.is_tarfile(archive):
        with tarfile.open(archive, "r:*") as tf:
            tf.extractall(dest, filter="data")
    else:
        # Raw binary – just copy it as-is
        shutil.copy2(archive, dest / archive.name)
        return dest

    # If there is exactly one top-level directory, return it
    top = [p for p in dest.iterdir() if not p.name.startswith(".")]
    if len(top) == 1 and top[0].is_dir():
        return top[0]
    return dest


def inventory(root: Path) -> dict[str, Path]:
    """Return ``{relative_path: absolute_path}`` for every file under *root*."""
    result: dict[str, Path] = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        dp = Path(dirpath)
        for fn in filenames:
            fp = dp / fn
            rel = str(fp.relative_to(root))
            result[rel] = fp
    return result


# ── comparison ──────────────────────────────────────────────────────


class FileEntry:
    """Metadata about a single file in the inventory."""

    __slots__ = ("path", "size", "sha256")

    def __init__(self, path: Path) -> None:
        self.path = path
        self.size = path.stat().st_size
        self.sha256 = sha256_file(path)


class CompareResult:
    """Result of comparing two firmware trees."""

    def __init__(self) -> None:
        self.only_a: list[str] = []
        self.only_b: list[str] = []
        self.identical: list[str] = []
        self.different: list[tuple[str, FileEntry, FileEntry]] = []

    @property
    def total_files(self) -> int:
        return (len(self.only_a) + len(self.only_b)
                + len(self.identical) + len(self.different))

    @property
    def has_differences(self) -> bool:
        return bool(self.only_a or self.only_b or self.different)


def compare_trees(inv_a: dict[str, Path],
                  inv_b: dict[str, Path]) -> CompareResult:
    """Compare two file inventories and return a :class:`CompareResult`."""
    result = CompareResult()
    all_keys = sorted(set(inv_a) | set(inv_b))

    for key in all_keys:
        if key not in inv_b:
            result.only_a.append(key)
        elif key not in inv_a:
            result.only_b.append(key)
        else:
            entry_a = FileEntry(inv_a[key])
            entry_b = FileEntry(inv_b[key])
            if entry_a.sha256 == entry_b.sha256:
                result.identical.append(key)
            else:
                result.different.append((key, entry_a, entry_b))

    return result


def _human_size(n: int) -> str:
    """Return a human-readable file size string."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n:.1f} TB"


def format_report(result: CompareResult, label_a: str, label_b: str) -> str:
    """Format the comparison result as a human-readable report."""
    lines: list[str] = []
    sep = "═" * 72

    lines.append(sep)
    lines.append("  FIRMWARE COMPARISON REPORT")
    lines.append(sep)
    lines.append(f"  A: {label_a}")
    lines.append(f"  B: {label_b}")
    lines.append(sep)
    lines.append("")

    lines.append(f"  Total files examined: {result.total_files}")
    lines.append(f"  Identical:           {len(result.identical)}")
    lines.append(f"  Different:           {len(result.different)}")
    lines.append(f"  Only in A:           {len(result.only_a)}")
    lines.append(f"  Only in B:           {len(result.only_b)}")
    lines.append("")

    if result.only_a:
        lines.append("─── Files only in A ──────────────────────────────────")
        for f in sorted(result.only_a):
            lines.append(f"  + {f}")
        lines.append("")

    if result.only_b:
        lines.append("─── Files only in B ──────────────────────────────────")
        for f in sorted(result.only_b):
            lines.append(f"  + {f}")
        lines.append("")

    if result.different:
        lines.append("─── Files that differ ────────────────────────────────")
        for rel, ea, eb in sorted(result.different, key=lambda t: t[0]):
            lines.append(f"  ≠ {rel}")
            lines.append(f"      A: {_human_size(ea.size)}  sha256={ea.sha256[:16]}…")
            lines.append(f"      B: {_human_size(eb.size)}  sha256={eb.sha256[:16]}…")
        lines.append("")

    if not result.has_differences:
        lines.append("  ✓ The two firmware images are IDENTICAL.")
    else:
        lines.append(
            f"  ✗ {len(result.different) + len(result.only_a) + len(result.only_b)} "
            f"difference(s) found."
        )
    lines.append(sep)
    return "\n".join(lines) + "\n"


# ── resolve input ──────────────────────────────────────────────────


def resolve_input(path_or_url: str, work_dir: Path) -> Path:
    """Return a local :class:`Path` for *path_or_url*.

    Downloads URLs into *work_dir* first.  Returns the original local
    path unchanged.
    """
    if is_url(path_or_url):
        return download_file(path_or_url, work_dir)
    p = Path(path_or_url)
    if not p.exists():
        raise FileNotFoundError(f"Input not found: {path_or_url}")
    return p


# ── CLI ────────────────────────────────────────────────────────────


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="firmware_tools.rom_compare",
        description=(
            "Download and compare two firmware/ROM files.  Accepts local "
            "paths or HTTP(S) URLs.  ZIP and tar archives are automatically "
            "extracted and their contents compared file-by-file."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m firmware_tools fw_a.zip fw_b.zip\n"
            "  python -m firmware_tools https://host/a.zip https://host/b.zip\n"
            "  python -m firmware_tools a.zip b.zip --output report.txt\n"
        ),
    )
    parser.add_argument("file_a", help="First firmware file (path or URL)")
    parser.add_argument("file_b", help="Second firmware file (path or URL)")
    parser.add_argument(
        "--output", "-o", default="",
        help="Write comparison report to this file (default: stdout)",
    )
    parser.add_argument(
        "--keep-temp", action="store_true", default=False,
        help="Keep temporary download/extraction directories",
    )
    return parser.parse_args(argv)


def run(file_a: str, file_b: str,
        output: str = "", keep_temp: bool = False) -> CompareResult:
    """Execute the full compare workflow and return the result."""
    tmp = Path(tempfile.mkdtemp(prefix="rom_compare_"))
    dl_dir = tmp / "downloads"
    ext_a = tmp / "extract_a"
    ext_b = tmp / "extract_b"
    dl_dir.mkdir()
    ext_a.mkdir()
    ext_b.mkdir()

    try:
        # 1. Resolve inputs (download if URL)
        print(f"[1/3] Resolving inputs …")
        local_a = resolve_input(file_a, dl_dir)
        local_b = resolve_input(file_b, dl_dir)

        # 2. Extract archives
        print(f"[2/3] Extracting archives …")
        root_a = extract_archive(local_a, ext_a)
        root_b = extract_archive(local_b, ext_b)

        # 3. Compare
        print(f"[3/3] Comparing contents …")
        inv_a = inventory(root_a)
        inv_b = inventory(root_b)

        result = compare_trees(inv_a, inv_b)
        report = format_report(result, file_a, file_b)

        if output:
            Path(output).write_text(report, encoding="utf-8")
            print(f"Report written to {output}")
        else:
            print(report)

        return result
    finally:
        if not keep_temp:
            shutil.rmtree(tmp, ignore_errors=True)
        else:
            print(f"Temporary files kept at: {tmp}")


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    result = run(args.file_a, args.file_b,
                 output=args.output, keep_temp=args.keep_temp)
    sys.exit(0 if not result.has_differences else 1)
