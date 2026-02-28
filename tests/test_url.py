"""
Tests for URL normalisation and path helpers.
"""

import unittest
from pathlib import Path

from web_crawler.utils.url import normalise_url, url_key, url_to_local_path


class TestNormaliseUrl(unittest.TestCase):
    BASE = "https://example.com"
    PAGE = "https://example.com/blog/post.html"

    def test_absolute_same_host(self):
        result = normalise_url(
            "https://example.com/images/logo.png", self.PAGE, self.BASE
        )
        self.assertEqual(result, "https://example.com/images/logo.png")

    def test_relative_path(self):
        result = normalise_url("../images/logo.png", self.PAGE, self.BASE)
        self.assertEqual(result, "https://example.com/images/logo.png")

    def test_root_relative(self):
        result = normalise_url("/css/style.css", self.PAGE, self.BASE)
        self.assertEqual(result, "https://example.com/css/style.css")

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
            "/css/style.css?202406291158020553184798", self.PAGE, self.BASE
        )
        self.assertEqual(result, "https://example.com/css/style.css")

    def test_meaningful_query_kept(self):
        result = normalise_url(
            "/search?q=python&page=2", self.PAGE, self.BASE
        )
        self.assertIn("q=python", result)

    def test_comma_ending_rejected(self):
        result = normalise_url("/g,", self.PAGE, self.BASE)
        self.assertIsNone(result)

    def test_http_upgraded_to_https_when_base_is_https(self):
        """http:// link on an https:// site must be upgraded to https://."""
        result = normalise_url(
            "http://example.com/page.html", self.PAGE, self.BASE
        )
        self.assertEqual(result, "https://example.com/page.html")

    def test_https_preserved_when_base_is_https(self):
        """https:// link on an https:// site stays https://."""
        result = normalise_url(
            "https://example.com/page.html", self.PAGE, self.BASE
        )
        self.assertEqual(result, "https://example.com/page.html")

    def test_http_base_keeps_http(self):
        """When the base is http://, links stay http://."""
        result = normalise_url(
            "http://example.com/page.html",
            "http://example.com/index.html",
            "http://example.com",
        )
        self.assertEqual(result, "http://example.com/page.html")



class TestUrlKey(unittest.TestCase):
    def test_strips_query(self):
        key = url_key("https://example.com/page.html?token=abc")
        self.assertEqual(key, "https://example.com/page.html")

    def test_strips_fragment(self):
        key = url_key("https://example.com/page.html#section")
        self.assertEqual(key, "https://example.com/page.html")


class TestUrlToLocalPath(unittest.TestCase):
    def test_root_url(self):
        result = url_to_local_path("https://example.com/", Path("out"))
        self.assertEqual(result, Path("out/index.html"))

    def test_html_file(self):
        result = url_to_local_path(
            "https://example.com/blog/post.html", Path("out")
        )
        self.assertEqual(result, Path("out/blog/post.html"))

    def test_image(self):
        result = url_to_local_path(
            "https://example.com/images/logo.png", Path("out")
        )
        self.assertEqual(result, Path("out/images/logo.png"))


if __name__ == "__main__":
    unittest.main()
