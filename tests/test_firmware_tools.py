"""Tests for firmware_tools modules."""

import os
import struct
import tempfile
import unittest

from firmware_tools.hwnp_parser import HWNP_MAGIC, HwnpFirmware, parse_hwnp
from firmware_tools.squashfs_extractor import find_squashfs
from firmware_tools.aes_decrypt import (
    AEST_HEADER_LEN,
    AEST_VERSION,
    AEST_FLAG_ENCRYPTED,
    KNOWN_CHIP_IDS,
    KEY_TEMPLATE,
    _looks_like_xml,
    derive_key,
    derive_key_aes256,
    decrypt_aest,
    decrypt_legacy,
    is_encrypted,
    parse_aest_header,
    parse_legacy_header,
)


class TestHwnpParser(unittest.TestCase):
    """Tests for HWNP firmware parser."""

    def test_non_hwnp_returns_none(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x00" * 1024)
            f.flush()
            self.assertIsNone(parse_hwnp(f.name))
        os.unlink(f.name)

    def test_hwnp_magic(self):
        self.assertEqual(HWNP_MAGIC, b"HWNP")


class TestSquashfsExtractor(unittest.TestCase):
    """Tests for SquashFS image finder."""

    def test_no_squashfs_in_random_data(self):
        data = bytes(range(256)) * 10
        self.assertEqual(find_squashfs(data), [])

    def test_find_squashfs_le_magic(self):
        data = bytearray(200)
        offset = 50
        data[offset : offset + 4] = b"hsqs"
        bytes_used = 100
        struct.pack_into("<Q", data, offset + 40, bytes_used)
        results = find_squashfs(bytes(data))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], (offset, bytes_used))


class TestAesDecrypt(unittest.TestCase):
    """Tests for AES key derivation and XML detection."""

    def test_derive_key_length(self):
        for chip_id in KNOWN_CHIP_IDS:
            key = derive_key(chip_id)
            self.assertEqual(len(key), 16, f"Key for {chip_id} is {len(key)} bytes")

    def test_derive_key_known_value(self):
        key = derive_key("SD5116H")
        self.assertEqual(key, b"Df7!uiSD5116H9(l")

    def test_derive_key_different_ids(self):
        keys = set()
        for chip_id in KNOWN_CHIP_IDS:
            keys.add(derive_key(chip_id))
        self.assertEqual(len(keys), len(KNOWN_CHIP_IDS))

    def test_derive_key_aes256_length(self):
        for chip_id in KNOWN_CHIP_IDS:
            key = derive_key_aes256(chip_id)
            self.assertEqual(len(key), 32, f"AES-256 key for {chip_id}")

    def test_derive_key_aes256_bare(self):
        key = derive_key_aes256("")
        self.assertEqual(len(key), 32)

    def test_looks_like_xml_valid(self):
        self.assertTrue(_looks_like_xml(b"<?xml version='1.0'?>"))
        self.assertTrue(_looks_like_xml(b"<root>content</root>"))
        self.assertTrue(_looks_like_xml(b"<InternetGatewayDevice>"))
        self.assertTrue(_looks_like_xml(b"<Config attr='val'/>"))

    def test_looks_like_xml_invalid(self):
        self.assertFalse(_looks_like_xml(b""))
        self.assertFalse(_looks_like_xml(b"\x01\x00\x00\x00"))
        self.assertFalse(_looks_like_xml(b"<\x9a\x9f\xe6"))
        self.assertFalse(_looks_like_xml(b"not xml at all"))

    def test_is_encrypted(self):
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False, mode="wb") as f:
            f.write(b"\x01\x00\x00\x00" + b"\xff" * 100)
            f.flush()
            self.assertTrue(is_encrypted(f.name))
        os.unlink(f.name)

    def test_is_not_encrypted(self):
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False, mode="wb") as f:
            f.write(b"<?xml version='1.0'?><root/>")
            f.flush()
            self.assertFalse(is_encrypted(f.name))
        os.unlink(f.name)


class TestAestFormat(unittest.TestCase):
    """Test AEST header parsing (from decompiled hw_ssp_aescrypt.h)."""

    def test_parse_valid_aest_header(self):
        iv = os.urandom(16)
        ciphertext = os.urandom(32)
        crc = b"\x00" * 4
        data = struct.pack("<II", AEST_VERSION, AEST_FLAG_ENCRYPTED)
        data += iv + ciphertext + crc
        result = parse_aest_header(data)
        self.assertIsNotNone(result)
        version, flags, parsed_iv, parsed_ct = result
        self.assertEqual(version, AEST_VERSION)
        self.assertEqual(flags, AEST_FLAG_ENCRYPTED)
        self.assertEqual(parsed_iv, iv)
        self.assertEqual(parsed_ct, ciphertext)

    def test_parse_invalid_version(self):
        data = struct.pack("<II", 0x99, 0x01)
        data += b"\x00" * 16 + b"\x00" * 32 + b"\x00" * 4
        self.assertIsNone(parse_aest_header(data))

    def test_parse_legacy_header(self):
        ciphertext = os.urandom(32)
        data = struct.pack("<II", 0x01, 0xDEADBEEF) + ciphertext
        result = parse_legacy_header(data)
        self.assertIsNotNone(result)
        version, parsed_ct = result
        self.assertEqual(version, 0x01)


class TestAesEncryptDecryptRoundtrip(unittest.TestCase):
    """Test AES-128-CBC and AES-256-CBC encrypt/decrypt roundtrip."""

    def test_aes128_roundtrip(self):
        try:
            from firmware_tools.aes_decrypt import decrypt_aes_cbc
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
        except ImportError:
            self.skipTest("pycryptodome not installed")

        key = derive_key("SD5116H")
        plaintext = b"<?xml version='1.0'?><config><param>value</param></config>"
        iv = b"\x00" * 16

        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        decrypted = decrypt_aes_cbc(ciphertext, key, iv)
        self.assertEqual(decrypted, plaintext)

    def test_aes256_roundtrip(self):
        try:
            from firmware_tools.aes_decrypt import decrypt_aes_cbc
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
        except ImportError:
            self.skipTest("pycryptodome not installed")

        key = derive_key_aes256("SD5116H")
        plaintext = b"<?xml version='1.0'?><config>test</config>"
        iv = os.urandom(16)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        decrypted = decrypt_aes_cbc(ciphertext, key, iv)
        self.assertEqual(decrypted, plaintext)

    def test_decrypt_aest_with_fallback_key(self):
        """Test AEST decrypt with the fallback key."""
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
        except ImportError:
            self.skipTest("pycryptodome not installed")

        plaintext = b"<?xml version='1.0'?><config>aest</config>"
        key = derive_key_aes256("")
        iv = os.urandom(16)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        # Build AEST file: header + ciphertext + CRC
        header = struct.pack("<II", AEST_VERSION, AEST_FLAG_ENCRYPTED) + iv
        data = header + ciphertext + b"\x00\x00\x00\x00"

        result = decrypt_aest(data)
        self.assertIsNotNone(result)
        self.assertEqual(result, plaintext)


if __name__ == "__main__":
    unittest.main()
