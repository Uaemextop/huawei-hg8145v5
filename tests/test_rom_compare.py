"""
Tests for firmware_tools.rom_compare
"""

import os
import tempfile
import unittest
import zipfile
from pathlib import Path

from firmware_tools.rom_compare import (
    CompareResult,
    FileEntry,
    compare_trees,
    extract_archive,
    format_report,
    inventory,
    is_url,
    sha256_file,
    _human_size,
)


class TestIsUrl(unittest.TestCase):
    def test_https(self):
        self.assertTrue(is_url("https://example.com/fw.zip"))

    def test_http(self):
        self.assertTrue(is_url("http://example.com/fw.zip"))

    def test_local_path(self):
        self.assertFalse(is_url("/tmp/fw.zip"))

    def test_relative_path(self):
        self.assertFalse(is_url("firmware/fw.zip"))

    def test_empty(self):
        self.assertFalse(is_url(""))


class TestSha256File(unittest.TestCase):
    def test_known_content(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"hello firmware")
            f.flush()
            path = Path(f.name)
        try:
            import hashlib
            expected = hashlib.sha256(b"hello firmware").hexdigest()
            self.assertEqual(sha256_file(path), expected)
        finally:
            path.unlink()

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            path = Path(f.name)
        try:
            import hashlib
            expected = hashlib.sha256(b"").hexdigest()
            self.assertEqual(sha256_file(path), expected)
        finally:
            path.unlink()


class TestExtractArchive(unittest.TestCase):
    def test_extract_zip(self):
        """Extract a ZIP with two files."""
        tmp = Path(tempfile.mkdtemp())
        try:
            zp = tmp / "test.zip"
            with zipfile.ZipFile(zp, "w") as zf:
                zf.writestr("file1.txt", "alpha")
                zf.writestr("subdir/file2.txt", "beta")

            dest = tmp / "out"
            dest.mkdir()
            root = extract_archive(zp, dest)

            f1 = root / "file1.txt"
            f2 = root / "subdir" / "file2.txt"
            self.assertTrue(f1.exists())
            self.assertTrue(f2.exists())
            self.assertEqual(f1.read_text(), "alpha")
            self.assertEqual(f2.read_text(), "beta")
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_extract_zip_single_toplevel_dir(self):
        """When ZIP has one top-level dir, extraction root is that dir."""
        tmp = Path(tempfile.mkdtemp())
        try:
            zp = tmp / "test.zip"
            with zipfile.ZipFile(zp, "w") as zf:
                zf.writestr("firmware_v1/boot.img", "BOOT")
                zf.writestr("firmware_v1/system.img", "SYS")

            dest = tmp / "out"
            dest.mkdir()
            root = extract_archive(zp, dest)

            # Root should be the single top-level dir
            self.assertEqual(root.name, "firmware_v1")
            self.assertTrue((root / "boot.img").exists())
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_raw_binary_copied(self):
        """Non-archive files are copied as-is."""
        tmp = Path(tempfile.mkdtemp())
        try:
            raw = tmp / "boot.img"
            raw.write_bytes(b"\x00\x01\x02\x03")

            dest = tmp / "out"
            dest.mkdir()
            root = extract_archive(raw, dest)

            copied = root / "boot.img"
            self.assertTrue(copied.exists())
            self.assertEqual(copied.read_bytes(), b"\x00\x01\x02\x03")
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


class TestInventory(unittest.TestCase):
    def test_flat_dir(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            (tmp / "a.txt").write_text("A")
            (tmp / "b.txt").write_text("B")
            inv = inventory(tmp)
            self.assertEqual(sorted(inv.keys()), ["a.txt", "b.txt"])
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_nested_dir(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            sub = tmp / "sub"
            sub.mkdir()
            (sub / "c.bin").write_bytes(b"\xff")
            inv = inventory(tmp)
            self.assertIn(os.path.join("sub", "c.bin"), inv)
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_empty_dir(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            inv = inventory(tmp)
            self.assertEqual(inv, {})
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


class TestCompareTrees(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.dir_a = self.tmp / "a"
        self.dir_b = self.tmp / "b"
        self.dir_a.mkdir()
        self.dir_b.mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_identical(self):
        (self.dir_a / "x.txt").write_text("same")
        (self.dir_b / "x.txt").write_text("same")
        inv_a = inventory(self.dir_a)
        inv_b = inventory(self.dir_b)
        result = compare_trees(inv_a, inv_b)
        self.assertEqual(len(result.identical), 1)
        self.assertEqual(len(result.different), 0)
        self.assertFalse(result.has_differences)

    def test_different_content(self):
        (self.dir_a / "x.txt").write_text("version1")
        (self.dir_b / "x.txt").write_text("version2")
        inv_a = inventory(self.dir_a)
        inv_b = inventory(self.dir_b)
        result = compare_trees(inv_a, inv_b)
        self.assertEqual(len(result.different), 1)
        self.assertTrue(result.has_differences)

    def test_only_in_a(self):
        (self.dir_a / "extra.bin").write_bytes(b"\x00")
        (self.dir_a / "common.txt").write_text("ok")
        (self.dir_b / "common.txt").write_text("ok")
        inv_a = inventory(self.dir_a)
        inv_b = inventory(self.dir_b)
        result = compare_trees(inv_a, inv_b)
        self.assertEqual(result.only_a, ["extra.bin"])
        self.assertTrue(result.has_differences)

    def test_only_in_b(self):
        (self.dir_a / "common.txt").write_text("ok")
        (self.dir_b / "common.txt").write_text("ok")
        (self.dir_b / "new.dat").write_bytes(b"\xff")
        inv_a = inventory(self.dir_a)
        inv_b = inventory(self.dir_b)
        result = compare_trees(inv_a, inv_b)
        self.assertEqual(result.only_b, ["new.dat"])
        self.assertTrue(result.has_differences)

    def test_empty_trees(self):
        result = compare_trees({}, {})
        self.assertEqual(result.total_files, 0)
        self.assertFalse(result.has_differences)


class TestFormatReport(unittest.TestCase):
    def test_identical_report(self):
        r = CompareResult()
        r.identical = ["boot.img", "system.img"]
        report = format_report(r, "fw_a.zip", "fw_b.zip")
        self.assertIn("IDENTICAL", report)
        self.assertIn("fw_a.zip", report)
        self.assertIn("Identical:           2", report)

    def test_differences_report(self):
        r = CompareResult()
        r.only_a = ["elabel.dat"]
        r.only_b = ["demo.cfg"]
        report = format_report(r, "a.zip", "b.zip")
        self.assertIn("elabel.dat", report)
        self.assertIn("demo.cfg", report)
        self.assertIn("difference(s) found", report)


class TestHumanSize(unittest.TestCase):
    def test_bytes(self):
        self.assertEqual(_human_size(42), "42 B")

    def test_kilobytes(self):
        self.assertIn("KB", _human_size(2048))

    def test_megabytes(self):
        self.assertIn("MB", _human_size(5 * 1024 * 1024))

    def test_gigabytes(self):
        self.assertIn("GB", _human_size(3 * 1024 ** 3))


class TestCompareResult(unittest.TestCase):
    def test_total_files(self):
        r = CompareResult()
        r.only_a = ["a"]
        r.only_b = ["b", "c"]
        r.identical = ["d"]
        self.assertEqual(r.total_files, 4)

    def test_has_differences_false(self):
        r = CompareResult()
        r.identical = ["x"]
        self.assertFalse(r.has_differences)

    def test_has_differences_true_different(self):
        r = CompareResult()
        r.different = [("x", None, None)]
        self.assertTrue(r.has_differences)


class TestEndToEnd(unittest.TestCase):
    """End-to-end test: create two ZIPs and compare them."""

    def test_compare_two_zips(self):
        from firmware_tools.rom_compare import run

        tmp = Path(tempfile.mkdtemp())
        try:
            # Create ZIP A
            zip_a = tmp / "fw_a.zip"
            with zipfile.ZipFile(zip_a, "w") as zf:
                zf.writestr("boot.img", "BOOT_V1")
                zf.writestr("system.img", "SYSTEM_SAME")
                zf.writestr("elabel.dat", "ELABEL_DATA")

            # Create ZIP B
            zip_b = tmp / "fw_b.zip"
            with zipfile.ZipFile(zip_b, "w") as zf:
                zf.writestr("boot.img", "BOOT_V2")  # different
                zf.writestr("system.img", "SYSTEM_SAME")  # same
                zf.writestr("demo.cfg", "DEMO_CONFIG")  # only in B

            report_file = tmp / "report.txt"
            result = run(
                str(zip_a), str(zip_b),
                output=str(report_file),
            )

            self.assertTrue(result.has_differences)
            self.assertEqual(len(result.identical), 1)  # system.img
            self.assertEqual(len(result.different), 1)  # boot.img
            self.assertEqual(result.only_a, ["elabel.dat"])
            self.assertEqual(result.only_b, ["demo.cfg"])

            report_text = report_file.read_text()
            self.assertIn("FIRMWARE COMPARISON REPORT", report_text)
            self.assertIn("boot.img", report_text)
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
