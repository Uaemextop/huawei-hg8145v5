"""Tests for the Huawei HG8145V5 router crawler core logic."""

import os
import tempfile
import unittest

from crawler import HuaweiCrawler


class TestUrlNormalisation(unittest.TestCase):
    """Verify URL normalisation and deduplication helpers."""

    def setUp(self):
        self.crawler = HuaweiCrawler(
            host="192.168.100.1",
            username="test",
            password="test",
            output_dir=tempfile.mkdtemp(),
            max_depth=5,
            delay=0,
        )

    def test_normalise_strips_trailing_slash(self):
        url = "http://192.168.100.1/html/status/"
        result = HuaweiCrawler._normalise_url(url)
        self.assertEqual(result, "http://192.168.100.1/html/status")

    def test_normalise_preserves_path(self):
        url = "http://192.168.100.1/index.asp"
        result = HuaweiCrawler._normalise_url(url)
        self.assertEqual(result, "http://192.168.100.1/index.asp")

    def test_normalise_root(self):
        url = "http://192.168.100.1/"
        result = HuaweiCrawler._normalise_url(url)
        self.assertEqual(result, "http://192.168.100.1/")

    def test_is_same_host_true(self):
        self.assertTrue(
            self.crawler._is_same_host("http://192.168.100.1/index.asp"),
        )

    def test_is_same_host_false(self):
        self.assertFalse(
            self.crawler._is_same_host("http://example.com/index.asp"),
        )


class TestBinaryDetection(unittest.TestCase):
    """Verify binary vs text content detection."""

    def test_image_content_type(self):
        self.assertTrue(
            HuaweiCrawler._is_binary_content("image/png", "logo.png"),
        )

    def test_html_content_type(self):
        self.assertFalse(
            HuaweiCrawler._is_binary_content("text/html", "index.asp"),
        )

    def test_binary_extension(self):
        self.assertTrue(
            HuaweiCrawler._is_binary_content("", "font.woff2"),
        )

    def test_text_extension(self):
        self.assertFalse(
            HuaweiCrawler._is_binary_content("", "script.js"),
        )


class TestLinkExtraction(unittest.TestCase):
    """Verify link extraction from HTML content."""

    def setUp(self):
        self.crawler = HuaweiCrawler(
            host="192.168.100.1",
            username="test",
            password="test",
            output_dir=tempfile.mkdtemp(),
            max_depth=5,
            delay=0,
        )

    def test_extracts_script_src(self):
        html = '<script src="/resource/common/util.js"></script>'
        source = "http://192.168.100.1/index.asp"
        self.crawler._extract_links(html, source, 0)
        urls = [u for u, _ in self.crawler.queue]
        self.assertIn("http://192.168.100.1/resource/common/util.js", urls)

    def test_extracts_link_href(self):
        html = '<link href="/Cuscss/login.css" rel="stylesheet" />'
        source = "http://192.168.100.1/index.asp"
        self.crawler._extract_links(html, source, 0)
        urls = [u for u, _ in self.crawler.queue]
        self.assertIn("http://192.168.100.1/Cuscss/login.css", urls)

    def test_extracts_frame_src(self):
        html = '<frame src="/html/status/status.asp"></frame>'
        source = "http://192.168.100.1/main.asp"
        self.crawler._extract_links(html, source, 0)
        urls = [u for u, _ in self.crawler.queue]
        self.assertIn("http://192.168.100.1/html/status/status.asp", urls)

    def test_extracts_img_src(self):
        html = '<img src="/images/logo.gif" />'
        source = "http://192.168.100.1/index.asp"
        self.crawler._extract_links(html, source, 0)
        urls = [u for u, _ in self.crawler.queue]
        self.assertIn("http://192.168.100.1/images/logo.gif", urls)

    def test_extracts_css_url(self):
        html = 'background: url("/images/bg.png") no-repeat;'
        source = "http://192.168.100.1/Cuscss/login.css"
        self.crawler._extract_links(html, source, 0)
        urls = [u for u, _ in self.crawler.queue]
        self.assertIn("http://192.168.100.1/images/bg.png", urls)

    def test_extracts_setaction(self):
        html = "Form.setAction('/login.cgi');"
        source = "http://192.168.100.1/index.asp"
        self.crawler._extract_links(html, source, 0)
        urls = [u for u, _ in self.crawler.queue]
        self.assertIn("http://192.168.100.1/login.cgi", urls)

    def test_extracts_ajax_url(self):
        html = "url: '/asp/GetRandCount.asp',"
        source = "http://192.168.100.1/index.asp"
        self.crawler._extract_links(html, source, 0)
        urls = [u for u, _ in self.crawler.queue]
        self.assertIn("http://192.168.100.1/asp/GetRandCount.asp", urls)

    def test_ignores_javascript_urls(self):
        html = '<a href="javascript:void(0)">link</a>'
        source = "http://192.168.100.1/index.asp"
        self.crawler._extract_links(html, source, 0)
        urls = [u for u, _ in self.crawler.queue]
        for u in urls:
            self.assertNotIn("javascript", u)

    def test_ignores_external_hosts(self):
        html = '<a href="http://example.com/page">link</a>'
        source = "http://192.168.100.1/index.asp"
        self.crawler._extract_links(html, source, 0)
        urls = [u for u, _ in self.crawler.queue]
        for u in urls:
            self.assertIn("192.168.100.1", u)

    def test_resolves_relative_urls(self):
        html = '<script src="../common/util.js"></script>'
        source = "http://192.168.100.1/resource/page/index.asp"
        self.crawler._extract_links(html, source, 0)
        urls = [u for u, _ in self.crawler.queue]
        self.assertIn("http://192.168.100.1/resource/common/util.js", urls)


class TestPasswordEncoding(unittest.TestCase):
    """Verify the Base64 password encoding matches router expectations."""

    def test_password_base64(self):
        import base64
        password = "796cce597901a5cf"
        encoded = base64.b64encode(password.encode("utf-8")).decode("ascii")
        # The router JS uses base64encode(Password.value).
        self.assertEqual(encoded, "Nzk2Y2NlNTk3OTAxYTVjZg==")


if __name__ == "__main__":
    unittest.main()
