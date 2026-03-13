"""Tests for firmware_tools.firmware_analyzer module."""

import os
import struct
import tempfile
import unittest

from firmware_tools.firmware_analyzer import (
    HUAWEI_AES_KEY,
    HWNP_MAGIC,
    KNOWN_CREDENTIALS,
    SU_PUB_KEY_PEM,
    ZTE_MAGIC,
    find_der_certificates,
    find_pem_blocks,
    generate_report,
    parse_hwnp_header,
    scan_firmware_directory,
)


class TestHWNPParsing(unittest.TestCase):
    """Test HWNP firmware header parsing."""

    def test_valid_hwnp_header(self):
        """Test parsing a valid HWNP header."""
        header = b"HWNP" + b"\x00" * 32
        header += b"164C|15AD|;E8C|COMMON|" + b"\x00" * (256 - len(header))
        result = parse_hwnp_header(header)
        self.assertIsNotNone(result)
        self.assertEqual(result["magic"], "HWNP")
        self.assertTrue(result["encrypted"])
        self.assertIn("164C", result["product_ids"])

    def test_invalid_magic(self):
        """Test that non-HWNP data returns None."""
        result = parse_hwnp_header(b"\x00\x00\x00\x00" + b"\x00" * 252)
        self.assertIsNone(result)

    def test_hwnp_without_product_ids(self):
        """Test HWNP header without product ID separators."""
        header = b"HWNP" + b"\x00" * 252
        result = parse_hwnp_header(header)
        self.assertIsNotNone(result)
        self.assertEqual(result["magic"], "HWNP")

    def test_zte_magic_not_hwnp(self):
        """Test that ZTE magic is not parsed as HWNP."""
        result = parse_hwnp_header(ZTE_MAGIC + b"\x00" * 252)
        self.assertIsNone(result)


class TestPEMExtraction(unittest.TestCase):
    """Test PEM block extraction from binary data."""

    SAMPLE_CERT = (
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBkTCB+wIJAKHBfpHYDGkvMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl\n"
        "c3RjYTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBExDzANBgNVBAMM\n"
        "BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96LT+cKJr8p5g==\n"
        "-----END CERTIFICATE-----"
    )

    SAMPLE_PRIVKEY = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "Proc-Type: 4,ENCRYPTED\n"
        "DEK-Info: AES-256-CBC,7EC546FB34CA7CD5599763D8D9AE6AC9\n"
        "\n"
        "Ij5tz2EJwbh21X1KUJ+dct5qBIr2XkGxVFzKg5oDWSEF\n"
        "-----END RSA PRIVATE KEY-----"
    )

    SAMPLE_PUBKEY = (
        "-----BEGIN PUBLIC KEY-----\n"
        "MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAM22zaKq\n"
        "-----END PUBLIC KEY-----"
    )

    def test_find_certificate(self):
        """Test extracting certificate PEM blocks."""
        blocks = find_pem_blocks(self.SAMPLE_CERT.encode())
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0]["type"], "certificate")

    def test_find_encrypted_private_key(self):
        """Test extracting encrypted private key PEM blocks."""
        blocks = find_pem_blocks(self.SAMPLE_PRIVKEY.encode())
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0]["type"], "encrypted_private_key")

    def test_find_public_key(self):
        """Test extracting public key PEM blocks."""
        blocks = find_pem_blocks(self.SAMPLE_PUBKEY.encode())
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0]["type"], "public_key")

    def test_find_multiple_blocks(self):
        """Test extracting multiple PEM blocks from mixed data."""
        mixed = self.SAMPLE_CERT + "\nSome random data\n" + self.SAMPLE_PUBKEY
        blocks = find_pem_blocks(mixed.encode())
        self.assertEqual(len(blocks), 2)
        types = {b["type"] for b in blocks}
        self.assertIn("certificate", types)
        self.assertIn("public_key", types)

    def test_no_pem_blocks(self):
        """Test with data containing no PEM blocks."""
        blocks = find_pem_blocks(b"Just some random binary data with no PEM")
        self.assertEqual(len(blocks), 0)

    def test_pem_offset(self):
        """Test that PEM block offsets are correct."""
        prefix = b"HEADER_DATA_" * 10
        data = prefix + self.SAMPLE_CERT.encode()
        blocks = find_pem_blocks(data)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0]["offset"], len(prefix))


class TestDERDetection(unittest.TestCase):
    """Test DER certificate detection in binary data."""

    def test_find_der_certificate(self):
        """Test finding DER-encoded certificates."""
        # Create a fake DER certificate (ASN.1 SEQUENCE with reasonable length)
        cert_len = 500
        der_cert = b"\x30\x82" + struct.pack(">H", cert_len) + b"\x00" * cert_len
        data = b"\x00" * 100 + der_cert + b"\x00" * 100
        results = find_der_certificates(data)
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0]["type"], "der_certificate")
        self.assertEqual(results[0]["offset"], 100)

    def test_no_der_certificates(self):
        """Test with data containing no DER certificates."""
        data = b"\x00" * 1000
        results = find_der_certificates(data)
        self.assertEqual(len(results), 0)


class TestKnownCredentials(unittest.TestCase):
    """Test that known credentials are properly defined."""

    def test_hg8145v5_credentials(self):
        """Test HG8145V5 credentials exist."""
        self.assertIn("Huawei-HG8145V5", KNOWN_CREDENTIALS)
        creds = KNOWN_CREDENTIALS["Huawei-HG8145V5"]
        self.assertGreater(len(creds), 0)
        # Check telecomadmin exists
        users = [c["user"] for c in creds]
        self.assertIn("telecomadmin", users)

    def test_all_credentials_have_required_fields(self):
        """Test all credential entries have user, pass, context."""
        for device, creds in KNOWN_CREDENTIALS.items():
            for cred in creds:
                self.assertIn("user", cred, f"Missing 'user' in {device}")
                self.assertIn("pass", cred, f"Missing 'pass' in {device}")
                self.assertIn("context", cred, f"Missing 'context' in {device}")

    def test_known_aes_key(self):
        """Test the known AES key is defined."""
        self.assertEqual(len(HUAWEI_AES_KEY), 16)
        self.assertEqual(HUAWEI_AES_KEY, "Df7!ui%s9(lmV1L8")

    def test_su_pub_key_pem(self):
        """Test the su_pub_key PEM is properly formatted."""
        self.assertIn("BEGIN PUBLIC KEY", SU_PUB_KEY_PEM)
        self.assertIn("END PUBLIC KEY", SU_PUB_KEY_PEM)


class TestScanDirectory(unittest.TestCase):
    """Test firmware directory scanning."""

    def test_scan_empty_directory(self):
        """Test scanning an empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            results = scan_firmware_directory(tmpdir)
            self.assertEqual(len(results["firmware_files"]), 0)
            self.assertEqual(len(results["private_keys"]), 0)

    def test_scan_nonexistent_directory(self):
        """Test scanning a nonexistent directory."""
        results = scan_firmware_directory("/nonexistent/path/to/firmware")
        self.assertEqual(len(results["firmware_files"]), 0)

    def test_scan_with_pem_files(self):
        """Test scanning a directory with PEM files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a fake cert file
            cert_content = (
                "-----BEGIN CERTIFICATE-----\n"
                "MIIBkTCB+wIJAKHBfpHYDGkvMA0GCSqGSIb3DQEBCwUAMBExDzANBgNV\n"
                "-----END CERTIFICATE-----\n"
            )
            cert_path = os.path.join(tmpdir, "test.crt")
            with open(cert_path, "w") as f:
                f.write(cert_content)

            results = scan_firmware_directory(tmpdir)
            self.assertGreater(len(results["certificates"]), 0)

    def test_scan_with_bin_files(self):
        """Test scanning a directory with .bin firmware files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a fake HWNP firmware
            hwnp_data = b"HWNP" + b"\x00" * 252
            bin_path = os.path.join(tmpdir, "test.bin")
            with open(bin_path, "wb") as f:
                f.write(hwnp_data)

            results = scan_firmware_directory(tmpdir)
            self.assertEqual(len(results["firmware_files"]), 1)
            self.assertIn("HWNP", results["firmware_files"][0]["format"])


class TestReportGeneration(unittest.TestCase):
    """Test report generation."""

    def test_generate_report(self):
        """Test that report is generated successfully."""
        results = {
            "firmware_files": [
                {"path": "test.bin", "size": 1024, "format": "HWNP"}
            ],
            "certificates": [],
            "private_keys": [],
            "public_keys": [],
            "credentials": [],
            "encrypted_files": [],
            "capstone_analysis": [],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            report_file = generate_report(results, tmpdir)
            self.assertTrue(os.path.exists(report_file))
            with open(report_file, "r") as f:
                content = f.read()
            self.assertIn("Firmware Analysis Report", content)
            self.assertIn("test.bin", content)
            self.assertIn(HUAWEI_AES_KEY, content)

    def test_report_contains_credentials(self):
        """Test that report contains the credentials table."""
        results = {
            "firmware_files": [],
            "certificates": [],
            "private_keys": [],
            "public_keys": [],
            "credentials": [],
            "encrypted_files": [],
            "capstone_analysis": [],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            report_file = generate_report(results, tmpdir)
            with open(report_file, "r") as f:
                content = f.read()
            self.assertIn("telecomadmin", content)
            self.assertIn("admintelecom", content)
            self.assertIn("Default Credentials", content)


if __name__ == "__main__":
    unittest.main()
