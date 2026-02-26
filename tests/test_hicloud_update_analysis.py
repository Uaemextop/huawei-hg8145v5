"""Tests for firmware_tools.hicloud_update_analysis module."""

import json
import tempfile
import unittest
from pathlib import Path

from firmware_tools.hicloud_update_analysis import (
    HICLOUD_CDN,
    HICLOUD_DOWNLOAD_URL_PATTERN,
    HICLOUD_TDS_URL_PATTERN,
    VERIFIED_DOWNLOAD_URLS,
    FIRMWARE_CONTAINER_FORMAT,
    ONT_AUTH_PROTOCOL,
    UPGRADE_CHECK_XML_TEMPLATE,
    UPGRADE_CHECK_HASHES,
    UPGRADE_SCRIPT_FUNCTIONS,
    UPGRADE_ENCRYPTION_FLOW,
    HTTP_REQUEST_FORMAT,
    CDN_RESPONSE_HEADERS,
    URL_COMPONENTS,
    HiCloudAnalysisReport,
    decode_download_url,
    parse_firmware_header,
    build_login_request,
    build_firmware_check_request,
    get_report,
    scan_firmware_signatures,
    extract_hwnp_sections,
    extract_elf_info,
    extract_shell_scripts,
    attempt_decryption,
    analyze_firmware_binary,
)


class TestHiCloudCDN(unittest.TestCase):
    """Test CDN infrastructure metadata."""

    def test_frontend_host(self):
        self.assertEqual(HICLOUD_CDN["frontend"], "update.hicloud.com")

    def test_backend(self):
        self.assertIn("qcloud", HICLOUD_CDN["backend"])

    def test_storage(self):
        self.assertIn("OBS", HICLOUD_CDN["storage"])

    def test_cdn_ips(self):
        self.assertGreater(len(HICLOUD_CDN["cdn_ips"]), 5)

    def test_ports(self):
        self.assertIn(80, HICLOUD_CDN["ports"])
        self.assertIn(8180, HICLOUD_CDN["ports"])


class TestURLPatterns(unittest.TestCase):
    """Test URL pattern documentation."""

    def test_download_pattern(self):
        self.assertIn("update.hicloud.com", HICLOUD_DOWNLOAD_URL_PATTERN)
        self.assertIn("{auth_token}", HICLOUD_DOWNLOAD_URL_PATTERN)
        self.assertIn("HWHOTA", HICLOUD_DOWNLOAD_URL_PATTERN)

    def test_tds_pattern(self):
        self.assertIn(":8180", HICLOUD_TDS_URL_PATTERN)
        self.assertIn("TDS/data/files", HICLOUD_TDS_URL_PATTERN)


class TestVerifiedDownloads(unittest.TestCase):
    """Test verified download entries."""

    def test_not_empty(self):
        self.assertGreater(len(VERIFIED_DOWNLOAD_URLS), 0)

    def test_ws7200_entry(self):
        ws = [d for d in VERIFIED_DOWNLOAD_URLS if "WS7200" in d["product"]]
        self.assertEqual(len(ws), 1)
        self.assertEqual(ws[0]["size_bytes"], 27002944)
        self.assertEqual(ws[0]["md5"], "2391af62e6523f051ddc90e0dca1e926")
        self.assertEqual(ws[0]["status"], "live")


class TestFirmwareContainerFormat(unittest.TestCase):
    """Test firmware container format documentation."""

    def test_magic(self):
        self.assertEqual(FIRMWARE_CONTAINER_FORMAT["magic"], 0x1A0FF01A)

    def test_header_size(self):
        self.assertEqual(FIRMWARE_CONTAINER_FORMAT["header_size"], 32)

    def test_has_fields(self):
        self.assertIn("fields", FIRMWARE_CONTAINER_FORMAT)
        self.assertIn(0x00, FIRMWARE_CONTAINER_FORMAT["fields"])
        self.assertIn(0x04, FIRMWARE_CONTAINER_FORMAT["fields"])
        self.assertIn(0x30, FIRMWARE_CONTAINER_FORMAT["fields"])


class TestAuthProtocol(unittest.TestCase):
    """Test ONT authentication protocol metadata."""

    def test_login_endpoint(self):
        self.assertEqual(ONT_AUTH_PROTOCOL["login_endpoint"], "/login.cgi")

    def test_firmware_page(self):
        self.assertEqual(ONT_AUTH_PROTOCOL["firmware_page"], "/firmware.asp")

    def test_token_fields(self):
        self.assertIn("onttoken", ONT_AUTH_PROTOCOL["token_fields"])
        self.assertIn("x.X_HW_Token", ONT_AUTH_PROTOCOL["token_fields"])
        self.assertIn("UploadToken", ONT_AUTH_PROTOCOL["token_fields"])

    def test_login_params(self):
        params = ONT_AUTH_PROTOCOL["login_parameters"]
        self.assertIn("UserName", params)
        self.assertIn("PassWord", params)

    def test_ssl_config(self):
        ssl = ONT_AUTH_PROTOCOL["ssl_config"]
        self.assertIn("Huawei Root CA", ssl["ca"])
        self.assertIn("rnd-ont.huawei.com", ssl["device_cert_cn"])

    def test_huawei_internal_endpoints(self):
        eps = ONT_AUTH_PROTOCOL["huawei_internal_endpoints"]
        self.assertIn("login.huawei.com", eps["login_token"])


class TestUpgradeCheckXML(unittest.TestCase):
    """Test embedded UpgradeCheck XML template."""

    def test_has_upgradecheck_tags(self):
        self.assertIn("<upgradecheck>", UPGRADE_CHECK_XML_TEMPLATE)
        self.assertIn("</upgradecheck>", UPGRADE_CHECK_XML_TEMPLATE)

    def test_has_hardware_checks(self):
        self.assertIn("HardVerCheck", UPGRADE_CHECK_XML_TEMPLATE)
        self.assertIn("WifiChipCheck", UPGRADE_CHECK_XML_TEMPLATE)
        self.assertIn("OpticalCheck", UPGRADE_CHECK_XML_TEMPLATE)

    def test_hashes(self):
        self.assertIn("UpgradeCheck.xml", UPGRADE_CHECK_HASHES)
        self.assertEqual(len(UPGRADE_CHECK_HASHES["UpgradeCheck.xml"]), 64)


class TestUpgradeScript(unittest.TestCase):
    """Test upgrade script function documentation."""

    def test_functions_not_empty(self):
        self.assertGreater(len(UPGRADE_SCRIPT_FUNCTIONS), 4)

    def test_create_log(self):
        self.assertIn("HW_Script_CreateLogFile", UPGRADE_SCRIPT_FUNCTIONS)

    def test_encrypt_function(self):
        self.assertIn("HW_Script_Encrypt", UPGRADE_SCRIPT_FUNCTIONS)
        self.assertIn("aescrypt2", UPGRADE_SCRIPT_FUNCTIONS["HW_Script_Encrypt"])


class TestEncryptionFlow(unittest.TestCase):
    """Test encryption flow documentation."""

    def test_aes_key(self):
        self.assertEqual(UPGRADE_ENCRYPTION_FLOW["key"], "Df7!ui%s9(lmV1L8")

    def test_modes(self):
        modes = UPGRADE_ENCRYPTION_FLOW["aescrypt2_modes"]
        self.assertIn(0, modes)
        self.assertIn(1, modes)
        self.assertIn("Encrypt", modes[0])
        self.assertIn("Decrypt", modes[1])


class TestDecodeDownloadURL(unittest.TestCase):
    """Test URL decoder."""

    def test_obs_url(self):
        url = (
            "http://update.hicloud.com/download/data/pub_13/"
            "HWHOTA_hota_900_9/5e/v3/ISJ7Xk-tTpGg6prrAbWycw/"
            "WS7200-20_11.0.5.5(C500)_main.bin"
        )
        result = decode_download_url(url)
        self.assertEqual(result["url_type"], "OBS download")
        self.assertEqual(result["components"]["bucket"], "pub_13")
        self.assertEqual(result["components"]["hash_prefix"], "5e")
        self.assertEqual(result["components"]["version_tag"], "v3")
        self.assertIn("auth_token_hex", result["components"])
        self.assertEqual(result["components"]["auth_token_length"], 16)

    def test_tds_url(self):
        url = (
            "http://update.hicloud.com:8180/TDS/data/files/"
            "p9/s92/G247/g0/v90201/f1/full/"
        )
        result = decode_download_url(url)
        self.assertEqual(result["url_type"], "TDS (legacy)")
        self.assertEqual(result["components"]["product"], "p9")
        self.assertEqual(result["components"]["series"], "s92")
        self.assertEqual(result["components"]["group"], "G247")

    def test_unknown_url(self):
        result = decode_download_url("http://example.com/test")
        self.assertNotIn("url_type", result)


class TestParseFirmwareHeader(unittest.TestCase):
    """Test firmware header parser."""

    def test_encrypted_container(self):
        import struct
        header = struct.pack("<IIIII", 1, 0x1A0FF01A, 0x00020001, 32, 0x0F)
        header += b"\x00" * 12 + b"\x00" * 16 + b"\xAB" * 200
        result = parse_firmware_header(header)
        self.assertEqual(result["format"], "Huawei Encrypted Firmware Container")
        self.assertTrue(result["encrypted"])
        self.assertEqual(result["header_size"], 32)
        self.assertEqual(result["payload_offset"], 0x30)

    def test_hwnp_header(self):
        header = b"HWNP" + b"\x00" * 252
        result = parse_firmware_header(header)
        self.assertEqual(result["format"], "HWNP (Huawei Network Product)")
        self.assertFalse(result["encrypted"])

    def test_gzip_header(self):
        header = b"\x1f\x8b\x08\x00" + b"\x00" * 252
        result = parse_firmware_header(header)
        self.assertEqual(result["format"], "GZIP compressed")

    def test_too_short(self):
        result = parse_firmware_header(b"\x00" * 10)
        self.assertIn("error", result)


class TestBuildLoginRequest(unittest.TestCase):
    """Test login request builder."""

    def test_basic_login(self):
        req = build_login_request("192.168.1.1", "admin", "secret", "tok123")
        self.assertEqual(req["method"], "POST")
        self.assertIn("/login.cgi", req["url"])
        self.assertIn("UserName=admin", req["body"])
        self.assertIn("PassWord=secret", req["body"])
        self.assertIn("x.X_HW_Token=tok123", req["body"])
        self.assertEqual(req["headers"]["User-Agent"], "HuaweiHomeGateway")


class TestBuildFirmwareCheckRequest(unittest.TestCase):
    """Test firmware check request builder."""

    def test_basic(self):
        req = build_firmware_check_request("192.168.1.1")
        self.assertEqual(req["method"], "GET")
        self.assertIn("/firmware.asp", req["url"])

    def test_with_cookie(self):
        req = build_firmware_check_request("192.168.1.1", cookie="sid=abc")
        self.assertEqual(req["headers"]["Cookie"], "sid=abc")


class TestAnalysisReport(unittest.TestCase):
    """Test HiCloudAnalysisReport dataclass."""

    def test_get_report(self):
        report = get_report()
        self.assertIsInstance(report, HiCloudAnalysisReport)
        self.assertIn("update.hicloud.com",
                       report.cdn_infrastructure["frontend"])

    def test_to_dict(self):
        report = get_report()
        d = report.to_dict()
        self.assertIn("cdn_infrastructure", d)
        self.assertIn("ont_auth_protocol", d)
        self.assertIn("upgrade_check_xml", d)
        self.assertIn("verified_downloads", d)

    def test_save_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report = get_report()
            path = report.save(Path(tmpdir) / "test.json")
            self.assertTrue(path.exists())
            data = json.loads(path.read_text())
            self.assertIn("cdn_infrastructure", data)

    def test_print_summary(self):
        report = get_report()
        report.print_summary()  # Should not raise


class TestScanFirmwareSignatures(unittest.TestCase):
    """Test firmware signature scanning."""

    def test_find_hwnp(self):
        data = b"\x00" * 100 + b"HWNP" + b"\x00" * 100
        sigs = scan_firmware_signatures(data)
        self.assertEqual(len(sigs), 1)
        self.assertEqual(sigs[0]["signature"], "HWNP (Huawei Network Product)")
        self.assertEqual(sigs[0]["offset"], 100)

    def test_find_elf(self):
        data = b"\x7fELF" + b"\x00" * 200
        sigs = scan_firmware_signatures(data)
        self.assertTrue(any("ELF" in s["signature"] for s in sigs))

    def test_find_gzip(self):
        data = b"\x00" * 50 + b"\x1f\x8b\x08" + b"\x00" * 200
        sigs = scan_firmware_signatures(data)
        self.assertTrue(any("GZIP" in s["signature"] for s in sigs))

    def test_find_multiple(self):
        data = b"HWNP" + b"\x00" * 50 + b"\x7fELF" + b"\x00" * 100
        sigs = scan_firmware_signatures(data)
        self.assertGreaterEqual(len(sigs), 2)

    def test_empty_data(self):
        sigs = scan_firmware_signatures(b"\x00" * 100)
        self.assertEqual(len(sigs), 0)


class TestExtractHwnpSections(unittest.TestCase):
    """Test HWNP section extraction."""

    def test_single_hwnp(self):
        data = b"HWNP" + b"\x00" * 60 + b"\x00" * 200
        sections = extract_hwnp_sections(data)
        self.assertEqual(len(sections), 1)
        self.assertEqual(sections[0]["magic"], "HWNP")

    def test_hwnp_with_product_list(self):
        data = (b"HWNP" + b"\x00" * 28 +
                b"120|130|140\x00" + b"\x00" * 200)
        sections = extract_hwnp_sections(data)
        self.assertEqual(len(sections), 1)
        if "product_list" in sections[0]:
            self.assertIn("120", sections[0]["product_list"])

    def test_multiple_hwnp(self):
        data = b"HWNP" + b"\x00" * 100 + b"HWNP" + b"\x00" * 100
        sections = extract_hwnp_sections(data)
        self.assertEqual(len(sections), 2)

    def test_no_hwnp(self):
        data = b"\x00" * 200
        sections = extract_hwnp_sections(data)
        self.assertEqual(len(sections), 0)


class TestExtractElfInfo(unittest.TestCase):
    """Test ELF binary info extraction."""

    def test_arm_elf(self):
        import struct
        # Build minimal ELF32 ARM LE header
        header = b"\x7fELF"                   # magic
        header += bytes([1, 1, 1, 0])         # class=32, LE, ver, osabi
        header += b"\x00" * 8                 # padding
        header += struct.pack("<HH", 2, 0x28) # type=EXEC, machine=ARM
        header += struct.pack("<I", 1)        # version
        header += struct.pack("<I", 0x8000)   # entry
        header += struct.pack("<I", 0x34)     # phoff
        header += struct.pack("<I", 0x100)    # shoff
        header += struct.pack("<I", 0)        # flags
        header += struct.pack("<HHH", 52, 32, 0)  # ehsize, phentsize, phnum
        header += struct.pack("<HHH", 40, 2, 0)   # shentsize, shnum, shstrndx
        header += b"\x00" * 200

        info = extract_elf_info(header)
        self.assertEqual(info["architecture"], "ARM")
        self.assertEqual(info["class"], "32-bit")
        self.assertEqual(info["endian"], "Little")
        self.assertEqual(info["type"], "EXEC")

    def test_not_elf(self):
        info = extract_elf_info(b"\x00" * 200)
        self.assertIn("error", info)

    def test_too_short(self):
        info = extract_elf_info(b"\x7fELF")
        self.assertIn("error", info)


class TestExtractShellScripts(unittest.TestCase):
    """Test shell script extraction."""

    def test_extract_script(self):
        script_text = (
            b"#!/bin/sh\n"
            b"# Upgrade script for Huawei ONT router firmware\n"
            b"var_upgrade_log=/mnt/jffs2/upgrade_script_log.txt\n"
            b"HW_Script_Encrypt()\n{\n"
            b"  aescrypt2 0 $1 $1_tmp\n"
            b"  echo done\n}\n"
        )
        data = b"\x00" * 50 + script_text + b"\x00" * 50
        scripts = extract_shell_scripts(data)
        self.assertEqual(len(scripts), 1)
        self.assertTrue(scripts[0]["has_aescrypt"])
        self.assertIn("HW_Script_Encrypt", scripts[0]["functions"])

    def test_no_scripts(self):
        data = b"\x00" * 200
        scripts = extract_shell_scripts(data)
        self.assertEqual(len(scripts), 0)


class TestAttemptDecryption(unittest.TestCase):
    """Test firmware decryption attempts."""

    def test_not_encrypted_container(self):
        data = b"\x00" * 100
        result = attempt_decryption(data)
        self.assertFalse(result["format_detected"])

    def test_encrypted_container(self):
        import struct
        # Build a fake 0x1A0FF01A container with random payload
        header = struct.pack("<IIIII", 1, 0x1A0FF01A, 0x20001, 32, 0xF)
        header += b"\x00" * 12  # pad to 32 bytes
        padding = b"\x00" * 16
        import os
        payload = os.urandom(4096)
        data = header + padding + payload

        result = attempt_decryption(data)
        self.assertTrue(result["format_detected"])
        self.assertIn("payload_entropy", result)
        # Random data should not decrypt successfully
        self.assertFalse(result["decrypted"])

    def test_too_short(self):
        result = attempt_decryption(b"\x00" * 10)
        self.assertIn("too short", result["analysis"])


class TestAnalyzeFirmwareBinary(unittest.TestCase):
    """Test analyze_firmware_binary on synthetic data."""

    def test_analyze_synthetic(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            # Create a synthetic firmware with HWNP + ELF markers
            data = b"HWNP" + b"\x00" * 100
            data += b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 44
            data += b"#!/bin/sh\necho test upgrade\n" + b"\x00" * 100
            f.write(data)
            f.flush()

            result = analyze_firmware_binary(f.name)
            self.assertIn("header", result)
            self.assertIn("signatures", result)
            self.assertIn("hwnp_sections", result)
            self.assertGreater(len(result["hwnp_sections"]), 0)

            import os
            os.unlink(f.name)

    def test_analyze_nonexistent(self):
        result = analyze_firmware_binary("/nonexistent/file.bin")
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main()
