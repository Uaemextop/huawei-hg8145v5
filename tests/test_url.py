"""
Tests for URL normalisation and path helpers.
"""

import unittest
from pathlib import Path

from huawei_crawler.utils.url import normalise_url, url_key, url_to_local_path


class TestNormaliseUrl(unittest.TestCase):
    BASE = "http://192.168.100.1"
    PAGE = "http://192.168.100.1/html/ssmp/wlan.asp"

    def test_absolute_same_host(self):
        result = normalise_url(
            "http://192.168.100.1/images/logo.png", self.PAGE, self.BASE
        )
        self.assertEqual(result, "http://192.168.100.1/images/logo.png")

    def test_relative_path(self):
        result = normalise_url("../images/logo.png", self.PAGE, self.BASE)
        self.assertEqual(result, "http://192.168.100.1/html/images/logo.png")

    def test_root_relative(self):
        result = normalise_url("/resource/common/util.js", self.PAGE, self.BASE)
        self.assertEqual(result, "http://192.168.100.1/resource/common/util.js")

    def test_external_host_rejected(self):
        result = normalise_url("http://evil.com/hack.js", self.PAGE, self.BASE)
        self.assertIsNone(result)

    def test_data_url_rejected(self):
        result = normalise_url("data:image/png;base64,xxx", self.PAGE, self.BASE)
        self.assertIsNone(result)

    def test_javascript_url_rejected(self):
        result = normalise_url("javascript:void(0)", self.PAGE, self.BASE)
        self.assertIsNone(result)

    def test_cache_buster_stripped(self):
        result = normalise_url(
            "/Cuscss/login.css?202406291158020553184798", self.PAGE, self.BASE
        )
        self.assertEqual(result, "http://192.168.100.1/Cuscss/login.css")

    def test_meaningful_query_kept(self):
        result = normalise_url(
            "/cgi-bin/data.cgi?ObjPath=InternetGatewayDevice", self.PAGE, self.BASE
        )
        self.assertIn("ObjPath=InternetGatewayDevice", result)

    def test_comma_ending_rejected(self):
        result = normalise_url("/g,", self.PAGE, self.BASE)
        self.assertIsNone(result)

    def test_empty_string_rejected(self):
        result = normalise_url("", self.PAGE, self.BASE)
        self.assertIsNone(result)

    def test_hash_only_rejected(self):
        result = normalise_url("#section", self.PAGE, self.BASE)
        self.assertIsNone(result)


class TestUrlKey(unittest.TestCase):
    def test_strips_query(self):
        key = url_key("http://192.168.100.1/page.asp?token=abc")
        self.assertEqual(key, "http://192.168.100.1/page.asp")

    def test_strips_fragment(self):
        key = url_key("http://192.168.100.1/page.asp#section")
        self.assertEqual(key, "http://192.168.100.1/page.asp")


class TestUrlToLocalPath(unittest.TestCase):
    def test_root_url(self):
        result = url_to_local_path("http://192.168.100.1/", Path("out"))
        self.assertEqual(result, Path("out/index.html"))

    def test_asp_file(self):
        result = url_to_local_path(
            "http://192.168.100.1/html/ssmp/wlan.asp", Path("out")
        )
        self.assertEqual(result, Path("out/html/ssmp/wlan.asp"))

    def test_image(self):
        result = url_to_local_path(
            "http://192.168.100.1/images/logo.png", Path("out")
        )
        self.assertEqual(result, Path("out/images/logo.png"))


if __name__ == "__main__":
    unittest.main()
