"""Tests for crawl4ai.extensions.sites.moto_cds.MotoCDSModule.

Covers:
* URL matching for both CDS hosts (svcmot.cn and appspot.com).
* generate_index parses positive (proceed=true) responses correctly.
* generate_index handles negative (proceed=false) responses gracefully.
* generate_index handles non-JSON / error responses.
* FileEntry fields are populated correctly from contentResources.
* Custom GUIDs from MOTO_CDS_GUIDS env var are picked up.
"""

from __future__ import annotations

import json
import os
import unittest
from unittest.mock import MagicMock, patch

from crawl4ai.extensions.sites.moto_cds import MotoCDSModule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(
    status_code: int = 200,
    json_body: dict | None = None,
    text: str = "",
    headers: dict | None = None,
) -> MagicMock:
    """Build a mock requests.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.content = (text or json.dumps(json_body or {})).encode()
    if json_body is not None:
        resp.json.return_value = json_body
    else:
        resp.json.side_effect = ValueError("No JSON")
    resp.text = text or json.dumps(json_body or {})
    return resp


def _positive_ota_response() -> dict:
    """Return a ``proceed: true`` OTA response with firmware resources."""
    return {
        "proceed": True,
        "context": "ota",
        "contextKey": "abc123",
        "content": {
            "version": "Blur_Version.35.15.5.sofia.retail.en.US",
            "displayVersion": "Android 14 (U1TDS35.15-5)",
            "otaSourceSha1": "abc123",
            "otaTargetSha1": "def456",
            "preInstallNotes": "Security patch update",
            "upgradeNotification": "Your phone is being updated",
        },
        "contentTimestamp": 1700000000,
        "contentResources": [
            {
                "url": "https://android.googleapis.com/packages/ota/motorola/Blur_Version.35.15.5.sofia.retail.en.US.zip",
                "hash": "sha256:aabbccdd",
                "size": 1572864000,
                "contentType": "blur_ota",
            },
        ],
        "trackingId": "track-001",
        "reportingTags": None,
        "pollAfterSeconds": 172800,
        "smartUpdateBitmap": 7,
        "uploadFailureLogs": False,
    }


def _negative_ota_response() -> dict:
    """Return a ``proceed: false`` OTA response (no update available)."""
    return {
        "proceed": False,
        "context": "ota",
        "contextKey": "test-guid",
        "content": None,
        "contentTimestamp": 0,
        "contentResources": None,
        "trackingId": None,
        "reportingTags": None,
        "pollAfterSeconds": 172800,
        "smartUpdateBitmap": -1,
        "uploadFailureLogs": False,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestMotoCDSMatches(unittest.TestCase):
    """MotoCDSModule.matches() recognises CDS URLs."""

    def setUp(self):
        self.mod = MotoCDSModule()

    def test_svcmot_cn_host(self):
        self.assertTrue(
            self.mod.matches("https://moto-cds.svcmot.cn/cds/upgrade")
        )

    def test_appspot_host(self):
        self.assertTrue(
            self.mod.matches("https://moto-cds.appspot.com/cds/upgrade")
        )

    def test_svcmot_cn_root(self):
        self.assertTrue(self.mod.matches("https://moto-cds.svcmot.cn/"))

    def test_no_match_other_host(self):
        self.assertFalse(self.mod.matches("https://example.com/cds"))

    def test_no_match_similar_host(self):
        self.assertFalse(
            self.mod.matches("https://cds.svcmot.cn/something")
        )


class TestMotoCDSCheckUpgrade(unittest.TestCase):
    """MotoCDSModule._check_upgrade parses OTA responses."""

    def test_positive_response_returns_entries(self):
        sess = MagicMock()
        sess.post.return_value = _make_response(
            json_body=_positive_ota_response(),
            headers={"x-cds-content-exists": "true"},
        )

        device = {
            "guid": "abc123",
            "carrier": "retus",
            "country": "US",
            "label": "Test device",
        }

        entries = MotoCDSModule._check_upgrade(
            sess, "https://moto-cds.svcmot.cn", device, "ota",
        )

        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertIn("Blur_Version.35.15.5", entry["name"])
        self.assertIn("googleapis.com", entry["url"])
        self.assertEqual(entry["category"], "OTA firmware (ota)")
        self.assertIn("1.5 GB", entry["size"])
        self.assertEqual(entry["version"], "Android 14 (U1TDS35.15-5)")
        self.assertIn("hash=sha256:aabbccdd", entry["description"])

    def test_negative_response_returns_empty(self):
        sess = MagicMock()
        sess.post.return_value = _make_response(
            json_body=_negative_ota_response(),
            headers={"x-cds-content-exists": "false"},
        )

        device = {
            "guid": "test-guid",
            "carrier": "retus",
            "country": "US",
            "label": "Test device",
        }

        entries = MotoCDSModule._check_upgrade(
            sess, "https://moto-cds.svcmot.cn", device, "ota",
        )
        self.assertEqual(entries, [])

    def test_http_error_returns_empty(self):
        sess = MagicMock()
        sess.post.return_value = _make_response(
            status_code=500, text="Internal Server Error",
        )

        entries = MotoCDSModule._check_upgrade(
            sess, "https://moto-cds.svcmot.cn",
            {"guid": "x", "label": "X"},
            "ota",
        )
        self.assertEqual(entries, [])

    def test_non_json_response_returns_empty(self):
        sess = MagicMock()
        resp = _make_response(status_code=200, text="<html>Not JSON</html>")
        resp.json.side_effect = ValueError("No JSON")
        sess.post.return_value = resp

        entries = MotoCDSModule._check_upgrade(
            sess, "https://moto-cds.svcmot.cn",
            {"guid": "x", "label": "X"},
            "ota",
        )
        self.assertEqual(entries, [])

    def test_network_error_returns_empty(self):
        sess = MagicMock()
        sess.post.side_effect = ConnectionError("timeout")

        entries = MotoCDSModule._check_upgrade(
            sess, "https://moto-cds.svcmot.cn",
            {"guid": "x", "label": "X"},
            "ota",
        )
        self.assertEqual(entries, [])


class TestMotoCDSGenerateIndex(unittest.TestCase):
    """MotoCDSModule.generate_index orchestration."""

    @patch.dict(os.environ, {}, clear=False)
    @patch("time.sleep")
    def test_generate_index_no_updates(self, mock_sleep):
        """With all probes returning proceed=false, generate_index returns
        an empty list."""
        sess = MagicMock()
        # Landing page
        sess.get.return_value = _make_response(
            json_body=None,
            text="<html>Hello App Engine</html>",
            headers={"Server": "nginx/1.14.1"},
        )
        # All OTA checks return negative
        sess.post.return_value = _make_response(
            json_body=_negative_ota_response(),
            headers={"x-cds-content-exists": "false"},
        )

        mod = MotoCDSModule(session=sess)
        entries = mod.generate_index("https://moto-cds.svcmot.cn")

        self.assertEqual(entries, [])
        # Verify landing page was probed
        sess.get.assert_called_once()
        # Verify OTA API was probed (5 devices × 4 contexts = 20 calls)
        self.assertEqual(sess.post.call_count, 20)

    @patch.dict(os.environ, {"MOTO_CDS_GUIDS": "aaa,bbb"}, clear=False)
    @patch("time.sleep")
    def test_env_guids_are_probed(self, mock_sleep):
        """Custom GUIDs from MOTO_CDS_GUIDS are added to the probe list."""
        sess = MagicMock()
        sess.get.return_value = _make_response(
            text="<html></html>",
            headers={"Server": "nginx/1.14.1"},
        )
        sess.post.return_value = _make_response(
            json_body=_negative_ota_response(),
        )

        mod = MotoCDSModule(session=sess)
        entries = mod.generate_index("https://moto-cds.svcmot.cn")

        # 5 built-in + 2 env = 7 devices × 4 contexts = 28 calls
        self.assertEqual(sess.post.call_count, 28)

    @patch.dict(os.environ, {}, clear=False)
    @patch("time.sleep")
    def test_generate_index_with_update(self, mock_sleep):
        """When one probe returns proceed=true, generate_index returns
        the firmware entries."""
        sess = MagicMock()
        sess.get.return_value = _make_response(
            text="<html></html>",
            headers={"Server": "nginx/1.14.1"},
        )

        # First call returns positive, rest negative
        positive = _make_response(
            json_body=_positive_ota_response(),
            headers={"x-cds-content-exists": "true"},
        )
        negative = _make_response(
            json_body=_negative_ota_response(),
            headers={"x-cds-content-exists": "false"},
        )
        sess.post.side_effect = [positive] + [negative] * 19

        mod = MotoCDSModule(session=sess)
        entries = mod.generate_index("https://moto-cds.svcmot.cn")

        self.assertEqual(len(entries), 1)
        self.assertIn("Blur_Version", entries[0]["name"])
        self.assertIn("googleapis.com", entries[0]["url"])


class TestMotoCDSParseResponse(unittest.TestCase):
    """MotoCDSModule._parse_ota_response edge cases."""

    def test_multiple_resources(self):
        """Multiple contentResources produce multiple entries."""
        data = _positive_ota_response()
        data["contentResources"].append({
            "url": "https://cdn.example.com/delta.zip",
            "hash": "sha256:eeff",
            "size": 524288,
        })

        entries = MotoCDSModule._parse_ota_response(
            data,
            {"guid": "abc", "label": "Test"},
            "ota",
            "https://example.com/check",
        )
        self.assertEqual(len(entries), 2)
        self.assertIn("512 KB", entries[1]["size"])

    def test_empty_url_skipped(self):
        """Resources with empty/missing URL are skipped."""
        data = _positive_ota_response()
        data["contentResources"] = [{"url": "", "size": 100}]

        entries = MotoCDSModule._parse_ota_response(
            data,
            {"guid": "abc", "label": "Test"},
            "ota",
            "https://example.com/check",
        )
        self.assertEqual(entries, [])

    def test_missing_content_fields(self):
        """Gracefully handles missing content fields."""
        data = {
            "proceed": True,
            "content": None,
            "contentResources": [
                {"url": "https://dl.example.com/fw.zip"},
            ],
        }

        entries = MotoCDSModule._parse_ota_response(
            data,
            {"guid": "abc", "label": "Test"},
            "fota",
            "https://example.com/check",
        )
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["version"], "unknown")
        self.assertEqual(entries[0]["category"], "OTA firmware (fota)")


class TestMotoCDSSize(unittest.TestCase):
    """Size formatting in FileEntry."""

    def test_gb_size(self):
        data = _positive_ota_response()
        data["contentResources"][0]["size"] = 2_147_483_648  # 2 GB

        entries = MotoCDSModule._parse_ota_response(
            data, {"guid": "x", "label": "T"}, "ota", "url",
        )
        self.assertEqual(entries[0]["size"], "2.0 GB")

    def test_mb_size(self):
        data = _positive_ota_response()
        data["contentResources"][0]["size"] = 104_857_600  # 100 MB

        entries = MotoCDSModule._parse_ota_response(
            data, {"guid": "x", "label": "T"}, "ota", "url",
        )
        self.assertEqual(entries[0]["size"], "100.0 MB")

    def test_kb_size(self):
        data = _positive_ota_response()
        data["contentResources"][0]["size"] = 10240  # 10 KB

        entries = MotoCDSModule._parse_ota_response(
            data, {"guid": "x", "label": "T"}, "ota", "url",
        )
        self.assertEqual(entries[0]["size"], "10 KB")

    def test_no_size(self):
        data = _positive_ota_response()
        data["contentResources"][0].pop("size", None)

        entries = MotoCDSModule._parse_ota_response(
            data, {"guid": "x", "label": "T"}, "ota", "url",
        )
        self.assertEqual(entries[0]["size"], "")


if __name__ == "__main__":
    unittest.main()
