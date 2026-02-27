"""Tests for firmware_tools.fw_analysis module."""

import json
import tempfile
import unittest
from pathlib import Path

from firmware_tools.fw_analysis import (
    ACS_ENDPOINTS,
    CWMP_SPEC_PARAMS,
    FIRMWARE_CERTIFICATES,
    FIRMWARE_DOWNLOAD_PATHS,
    FIRMWARE_FILENAMES,
    FIRMWARE_KEYS,
    FIRMWARE_USER_AGENTS,
    ISP_OPERATORS,
    TR069_DOWNLOAD_FILETYPES,
    FirmwareAnalysisReport,
    get_report,
)


class TestFirmwareUserAgents(unittest.TestCase):
    """Test firmware-extracted User-Agent strings."""

    def test_cwmp_ua(self):
        self.assertEqual(FIRMWARE_USER_AGENTS["cwmp"], "HuaweiHomeGateway")

    def test_bulk_data_ua(self):
        self.assertEqual(FIRMWARE_USER_AGENTS["bulk_data"], "HW-FTTH")

    def test_ipmac_ua(self):
        self.assertEqual(FIRMWARE_USER_AGENTS["ipmac_report"], "HW_IPMAC_REPORT")

    def test_web_market_ua_contains_ie9(self):
        self.assertIn("MSIE 9.0", FIRMWARE_USER_AGENTS["web_market"])

    def test_http_client_ua_contains_ie8(self):
        self.assertIn("MSIE 8.0", FIRMWARE_USER_AGENTS["http_client"])

    def test_all_strings(self):
        for key, ua in FIRMWARE_USER_AGENTS.items():
            self.assertIsInstance(ua, str)
            self.assertGreater(len(ua), 0, f"UA for {key} is empty")


class TestISPOperators(unittest.TestCase):
    """Test ISP operator profiles extracted from firmware."""

    def test_not_empty(self):
        self.assertGreater(len(ISP_OPERATORS), 40)

    def test_megacable_present(self):
        self.assertIn("megacable", ISP_OPERATORS)

    def test_telmex_present(self):
        self.assertIn("telmex", ISP_OPERATORS)
        self.assertEqual(ISP_OPERATORS["telmex"]["country"], "MX")

    def test_totalplay_present(self):
        self.assertIn("totalplay", ISP_OPERATORS)

    def test_claro_present(self):
        self.assertIn("claro", ISP_OPERATORS)

    def test_entel_present(self):
        self.assertIn("entel", ISP_OPERATORS)

    def test_all_have_name(self):
        for key, isp in ISP_OPERATORS.items():
            self.assertIn("name", isp, f"ISP {key} missing 'name'")
            self.assertIn("country", isp, f"ISP {key} missing 'country'")

    def test_latam_operators(self):
        """Firmware should have multiple LATAM ISP profiles."""
        latam = [k for k, v in ISP_OPERATORS.items()
                 if v.get("country") in ("MX", "BR", "CL", "AR", "CO",
                                         "EC", "UY", "LATAM")]
        self.assertGreater(len(latam), 8)


class TestACSEndpoints(unittest.TestCase):
    """Test ACS endpoint list."""

    def test_not_empty(self):
        self.assertGreater(len(ACS_ENDPOINTS), 20)

    def test_megacable_endpoint(self):
        mega = [e for e in ACS_ENDPOINTS if e["isp"] == "megacable"]
        self.assertEqual(len(mega), 1)
        self.assertEqual(mega[0]["host"], "acsvip.megared.net.mx")
        self.assertEqual(mega[0]["port"], 7547)

    def test_telmex_endpoint(self):
        telmex = [e for e in ACS_ENDPOINTS if e["isp"] == "telmex"]
        self.assertGreater(len(telmex), 0)

    def test_all_have_required_fields(self):
        for ep in ACS_ENDPOINTS:
            self.assertIn("host", ep)
            self.assertIn("port", ep)
            self.assertIn("path", ep)
            self.assertIn("isp", ep)
            self.assertIn("protocol", ep)
            self.assertIn(ep["protocol"], ("http", "https"))

    def test_o3telecom_portal(self):
        o3 = [e for e in ACS_ENDPOINTS if "o3-telecom" in e["host"]]
        self.assertGreater(len(o3), 0, "O3 Telecom portal missing")

    def test_jetzbroadband_portal(self):
        jetz = [e for e in ACS_ENDPOINTS if "jetzbroadband" in e["host"]]
        self.assertGreater(len(jetz), 0, "Jetz Broadband portal missing")


class TestFirmwareCertificates(unittest.TestCase):
    """Test firmware certificate metadata."""

    def test_not_empty(self):
        self.assertGreater(len(FIRMWARE_CERTIFICATES), 3)

    def test_root_ca(self):
        self.assertIn("root_ca", FIRMWARE_CERTIFICATES)
        self.assertEqual(
            FIRMWARE_CERTIFICATES["root_ca"]["path"], "/etc/wap/root.crt"
        )

    def test_device_cert(self):
        self.assertIn("device_cert", FIRMWARE_CERTIFICATES)
        self.assertIn("ont.huawei.com",
                       FIRMWARE_CERTIFICATES["device_cert"]["subject"])

    def test_all_have_path(self):
        for key, cert in FIRMWARE_CERTIFICATES.items():
            self.assertIn("path", cert, f"Cert {key} missing 'path'")
            self.assertIn("purpose", cert, f"Cert {key} missing 'purpose'")


class TestFirmwareKeys(unittest.TestCase):
    """Test firmware key metadata."""

    def test_not_empty(self):
        self.assertGreater(len(FIRMWARE_KEYS), 3)

    def test_aes_config_key(self):
        self.assertIn("aes_config_key", FIRMWARE_KEYS)
        self.assertEqual(
            FIRMWARE_KEYS["aes_config_key"]["value"], "Df7!ui%s9(lmV1L8"
        )

    def test_su_public_key(self):
        self.assertIn("su_public_key", FIRMWARE_KEYS)
        self.assertEqual(FIRMWARE_KEYS["su_public_key"]["exponent"], 65537)

    def test_device_private_key(self):
        self.assertIn("device_private_key", FIRMWARE_KEYS)
        self.assertIn("AES-256-CBC",
                       FIRMWARE_KEYS["device_private_key"]["type"])


class TestFirmwareDownloadPaths(unittest.TestCase):
    """Test firmware download path list."""

    def test_not_empty(self):
        self.assertGreater(len(FIRMWARE_DOWNLOAD_PATHS), 10)

    def test_firmware_path(self):
        self.assertIn("/firmware/", FIRMWARE_DOWNLOAD_PATHS)

    def test_service_cwmp_path(self):
        self.assertIn("/service/cwmp", FIRMWARE_DOWNLOAD_PATHS)


class TestFirmwareFilenames(unittest.TestCase):
    """Test firmware filename list."""

    def test_not_empty(self):
        self.assertGreater(len(FIRMWARE_FILENAMES), 10)

    def test_eg8145v5(self):
        eg = [f for f in FIRMWARE_FILENAMES if "EG8145V5" in f]
        self.assertGreater(len(eg), 0)

    def test_hg8145v5(self):
        hg = [f for f in FIRMWARE_FILENAMES if "HG8145V5" in f]
        self.assertGreater(len(hg), 0)


class TestTR069DownloadFileTypes(unittest.TestCase):
    """Test TR-069 download file types."""

    def test_firmware_upgrade(self):
        self.assertEqual(TR069_DOWNLOAD_FILETYPES["1"],
                         "Firmware Upgrade Image")

    def test_web_content(self):
        self.assertEqual(TR069_DOWNLOAD_FILETYPES["2"], "Web Content")


class TestCWMPSpecParams(unittest.TestCase):
    """Test CWMP spec parameter documentation."""

    def test_not_empty(self):
        self.assertGreater(len(CWMP_SPEC_PARAMS), 10)

    def test_acs_url_len(self):
        self.assertIn("SSMP_SPEC_CWMP_ACSURLLEN", CWMP_SPEC_PARAMS)


class TestFirmwareAnalysisReport(unittest.TestCase):
    """Test FirmwareAnalysisReport dataclass."""

    def test_get_report(self):
        report = get_report()
        self.assertIsInstance(report, FirmwareAnalysisReport)
        self.assertEqual(report.firmware_version, "V500R022C00SPC340B019")

    def test_to_dict(self):
        report = get_report()
        d = report.to_dict()
        self.assertIn("firmware", d)
        self.assertIn("user_agents", d)
        self.assertIn("isp_operators", d)
        self.assertIn("acs_endpoints", d)
        self.assertIn("certificates", d)
        self.assertIn("keys", d)

    def test_save_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report = get_report()
            path = report.save(Path(tmpdir) / "test_report.json")
            self.assertTrue(path.exists())
            data = json.loads(path.read_text())
            self.assertIn("firmware", data)
            self.assertEqual(data["firmware"]["version"],
                             "V500R022C00SPC340B019")

    def test_aes_key_not_in_json_keys(self):
        """AES key value should not be serialized in JSON report keys."""
        report = get_report()
        d = report.to_dict()
        for key_name, key_data in d["keys"].items():
            self.assertNotIn("value", key_data,
                             f"Key {key_name} should not expose 'value'")


if __name__ == "__main__":
    unittest.main()
