"""
Tests for firmware analysis modules: fw_analyzer, binary_analyzer,
and extracted key files.
"""

import os
import unittest
from pathlib import Path

from firmware_tools.fw_analyzer import (
    BINARY_ANALYSIS,
    CERTIFICATES,
    DEFAULT_CREDENTIALS,
    ENCRYPTED_FILES,
    ENCRYPTION_KEYS,
    FIRMWARE_CREDENTIALS,
    FIRMWARE_REPOS,
    ISP_ACS_CREDENTIALS,
    PRIVATE_KEYS,
    REALFIRMWARE_NET_DEVICES,
    generate_report,
    get_all_keys_document,
)
from firmware_tools.binary_analyzer import (
    analyze_elf_sections,
    disassemble_arm_snippet,
    generate_binary_analysis_report,
    scan_binary_for_keys,
    scan_for_crypto_constants,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ------------------------------------------------------------------ #
# fw_analyzer data & report tests
# ------------------------------------------------------------------ #

class TestFwAnalyzer(unittest.TestCase):
    """Tests for firmware_tools.fw_analyzer data structures and reports."""

    def test_firmware_repos_not_empty(self):
        self.assertTrue(len(FIRMWARE_REPOS) > 0)

    def test_firmware_repos_all_strings(self):
        for repo in FIRMWARE_REPOS:
            self.assertIsInstance(repo, str)

    def test_realfirmware_devices_not_empty(self):
        self.assertTrue(len(REALFIRMWARE_NET_DEVICES) > 0)

    def test_realfirmware_devices_all_huawei(self):
        for dev in REALFIRMWARE_NET_DEVICES:
            self.assertTrue(
                dev.startswith("Huawei-"),
                f"{dev} does not start with 'Huawei-'",
            )

    def test_certificates_not_empty(self):
        self.assertTrue(len(CERTIFICATES) > 0)

    def test_certificates_have_descriptions(self):
        for path, desc in CERTIFICATES.items():
            self.assertIsInstance(desc, str)
            self.assertTrue(len(desc) > 0, f"Empty description for {path}")

    def test_private_keys_not_empty(self):
        self.assertTrue(len(PRIVATE_KEYS) > 0)

    def test_private_keys_have_required_fields(self):
        for path, info in PRIVATE_KEYS.items():
            self.assertIn("description", info, f"Missing 'description' in {path}")
            self.assertIn("encryption", info, f"Missing 'encryption' in {path}")

    def test_encryption_keys_not_empty(self):
        self.assertTrue(len(ENCRYPTION_KEYS) > 0)

    def test_aes_config_key_present(self):
        self.assertIn("aes_config_key", ENCRYPTION_KEYS)
        self.assertEqual(
            ENCRYPTION_KEYS["aes_config_key"]["value"],
            "Df7!ui%s9(lmV1L8",
        )

    def test_firmware_credentials_not_empty(self):
        self.assertTrue(len(FIRMWARE_CREDENTIALS) > 0)

    def test_default_credentials_not_empty(self):
        self.assertTrue(len(DEFAULT_CREDENTIALS) > 0)

    def test_default_credentials_have_required_fields(self):
        for cred in DEFAULT_CREDENTIALS:
            for key in ("user", "password", "service", "source"):
                self.assertIn(key, cred, f"Missing '{key}' in credential entry")

    def test_isp_acs_credentials_not_empty(self):
        self.assertTrue(len(ISP_ACS_CREDENTIALS) > 0)

    def test_encrypted_files_not_empty(self):
        self.assertTrue(len(ENCRYPTED_FILES) > 0)

    def test_binary_analysis_not_empty(self):
        self.assertTrue(len(BINARY_ANALYSIS) > 0)

    def test_generate_report_returns_string(self):
        report = generate_report()
        self.assertIsInstance(report, str)
        self.assertTrue(len(report) > 0)

    def test_generate_report_contains_sections(self):
        report = generate_report()
        for section in ("Certificates", "Private / Public Keys", "Credentials"):
            self.assertIn(section, report)

    def test_get_all_keys_document_returns_string(self):
        doc = get_all_keys_document()
        self.assertIsInstance(doc, str)
        self.assertTrue(len(doc) > 0)

    def test_get_all_keys_document_contains_key_info(self):
        doc = get_all_keys_document()
        self.assertIn("prvt.key", doc)
        self.assertIn("su_pub_key", doc)


# ------------------------------------------------------------------ #
# binary_analyzer tests
# ------------------------------------------------------------------ #

class TestBinaryAnalyzer(unittest.TestCase):
    """Tests for firmware_tools.binary_analyzer scanning and analysis."""

    def test_scan_binary_for_pem_header(self):
        data = b"\x00" * 16 + b"-----BEGIN CERTIFICATE-----" + b"\x00" * 16
        findings = scan_binary_for_keys(data)
        types = [f["type"] for f in findings]
        self.assertIn("pem_header", types)

    def test_scan_binary_for_aes_key(self):
        data = b"\x00" * 16 + b"Df7!ui%s9(lmV1L8" + b"\x00" * 16
        findings = scan_binary_for_keys(data)
        types = [f["type"] for f in findings]
        self.assertIn("aes_key", types)

    def test_scan_binary_for_credentials(self):
        data = b"\x00" * 16 + b"password=test" + b"\x00" * 16
        findings = scan_binary_for_keys(data)
        types = [f["type"] for f in findings]
        self.assertIn("credential", types)

    def test_scan_empty_binary(self):
        findings = scan_binary_for_keys(b"")
        self.assertEqual(findings, [])

    def test_disassemble_arm_snippet(self):
        arm_nop = b"\x00\x00\xa0\xe1"
        result = disassemble_arm_snippet(arm_nop)
        # If capstone is installed we expect output; otherwise an empty list
        if result:
            self.assertIsInstance(result[0], str)

    def test_disassemble_empty(self):
        result = disassemble_arm_snippet(b"")
        self.assertEqual(result, [])

    def test_analyze_elf_sections_valid(self):
        elf = b"\x7fELF" + b"\x01\x01\x01" + b"\x00" * 45
        info = analyze_elf_sections(elf)
        self.assertIn("architecture", info)
        self.assertTrue(info["valid_elf"])

    def test_analyze_elf_sections_not_elf(self):
        info = analyze_elf_sections(b"not an elf file at all")
        self.assertFalse(info["valid_elf"])

    def test_scan_for_crypto_constants_aes_sbox(self):
        data = b"\x00" * 16 + bytes([0x63, 0x7C, 0x77, 0x7B]) + b"\x00" * 16
        findings = scan_for_crypto_constants(data)
        types = [f["type"] for f in findings]
        self.assertIn("aes_sbox", types)

    def test_scan_for_crypto_constants_empty(self):
        findings = scan_for_crypto_constants(b"")
        self.assertEqual(findings, [])

    def test_generate_binary_analysis_report(self):
        findings = [
            {"type": "pem_header", "offset": 0, "description": "test", "data_preview": "x"},
        ]
        report = generate_binary_analysis_report(findings)
        self.assertIsInstance(report, str)
        self.assertTrue(len(report) > 0)


# ------------------------------------------------------------------ #
# Extracted key file existence and content tests
# ------------------------------------------------------------------ #

class TestExtractedKeys(unittest.TestCase):
    """Tests for files under extracted_keys/."""

    keys_dir = Path(REPO_ROOT) / "extracted_keys"

    def test_root_ca_exists(self):
        self.assertTrue((self.keys_dir / "root_ca.crt").exists())

    def test_pub_crt_exists(self):
        self.assertTrue((self.keys_dir / "pub.crt").exists())

    def test_plugroot_exists(self):
        self.assertTrue((self.keys_dir / "plugroot.crt").exists())

    def test_plugpub_exists(self):
        self.assertTrue((self.keys_dir / "plugpub.crt").exists())

    def test_su_pub_key_exists(self):
        self.assertTrue((self.keys_dir / "su_pub_key.pem").exists())

    def test_root_ca_is_pem(self):
        content = (self.keys_dir / "root_ca.crt").read_text()
        self.assertIn("BEGIN CERTIFICATE", content)

    def test_su_pub_key_is_pem(self):
        content = (self.keys_dir / "su_pub_key.pem").read_text()
        self.assertIn("BEGIN PUBLIC KEY", content)

    def test_analysis_report_exists(self):
        self.assertTrue(
            (self.keys_dir / "FIRMWARE_ANALYSIS_REPORT.md").exists(),
        )

    def test_keys_document_exists(self):
        self.assertTrue(
            (self.keys_dir / "PRIVATE_KEYS_AND_CREDENTIALS.md").exists(),
        )


if __name__ == "__main__":
    unittest.main()
