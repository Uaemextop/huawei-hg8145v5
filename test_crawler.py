"""Tests for the Huawei HG8145V5 router crawler core logic."""

import base64
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
            max_depth=0,
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
            max_depth=0,
            delay=0,
        )

    def _queued_urls(self):
        return [u for u, _ in self.crawler.queue]

    def test_extracts_script_src(self):
        html = '<script src="/resource/common/util.js"></script>'
        source = "http://192.168.100.1/index.asp"
        self.crawler._extract_links(html, source, 0)
        self.assertIn(
            "http://192.168.100.1/resource/common/util.js", self._queued_urls(),
        )

    def test_extracts_link_href(self):
        html = '<link href="/Cuscss/login.css" rel="stylesheet" />'
        source = "http://192.168.100.1/index.asp"
        self.crawler._extract_links(html, source, 0)
        self.assertIn(
            "http://192.168.100.1/Cuscss/login.css", self._queued_urls(),
        )

    def test_extracts_frame_src(self):
        html = '<frame src="/html/status/status.asp"></frame>'
        source = "http://192.168.100.1/main.asp"
        self.crawler._extract_links(html, source, 0)
        self.assertIn(
            "http://192.168.100.1/html/status/status.asp", self._queued_urls(),
        )

    def test_extracts_img_src(self):
        html = '<img src="/images/logo.gif" />'
        source = "http://192.168.100.1/index.asp"
        self.crawler._extract_links(html, source, 0)
        self.assertIn(
            "http://192.168.100.1/images/logo.gif", self._queued_urls(),
        )

    def test_extracts_css_url(self):
        html = 'background: url("/images/bg.png") no-repeat;'
        source = "http://192.168.100.1/Cuscss/login.css"
        self.crawler._extract_links(html, source, 0)
        self.assertIn(
            "http://192.168.100.1/images/bg.png", self._queued_urls(),
        )

    def test_extracts_setaction(self):
        html = "Form.setAction('/login.cgi');"
        source = "http://192.168.100.1/index.asp"
        self.crawler._extract_links(html, source, 0)
        self.assertIn(
            "http://192.168.100.1/login.cgi", self._queued_urls(),
        )

    def test_extracts_ajax_url(self):
        html = "url: '/asp/GetRandCount.asp',"
        source = "http://192.168.100.1/index.asp"
        self.crawler._extract_links(html, source, 0)
        self.assertIn(
            "http://192.168.100.1/asp/GetRandCount.asp", self._queued_urls(),
        )

    def test_ignores_javascript_urls(self):
        html = '<a href="javascript:void(0)">link</a>'
        source = "http://192.168.100.1/index.asp"
        self.crawler._extract_links(html, source, 0)
        for u in self._queued_urls():
            self.assertNotIn("javascript", u)

    def test_ignores_external_hosts(self):
        html = '<a href="http://example.com/page">link</a>'
        source = "http://192.168.100.1/index.asp"
        self.crawler._extract_links(html, source, 0)
        for u in self._queued_urls():
            self.assertIn("192.168.100.1", u)

    def test_resolves_relative_urls(self):
        html = '<script src="../common/util.js"></script>'
        source = "http://192.168.100.1/resource/page/index.asp"
        self.crawler._extract_links(html, source, 0)
        self.assertIn(
            "http://192.168.100.1/resource/common/util.js", self._queued_urls(),
        )

    def test_extracts_request_file(self):
        html = "Form.setAction('MdfPwdNormalNoLg.cgi?&z=foo&RequestFile=login.asp');"
        source = "http://192.168.100.1/index.asp"
        self.crawler._extract_links(html, source, 0)
        urls = self._queued_urls()
        self.assertTrue(
            any("login.asp" in u for u in urls),
            f"Expected a URL containing 'login.asp', got: {urls}",
        )

    def test_extracts_cgi_string_literal(self):
        html = "var url = 'FrameModeSwitch.cgi';"
        source = "http://192.168.100.1/index.asp"
        self.crawler._extract_links(html, source, 0)
        self.assertTrue(
            any("FrameModeSwitch.cgi" in u for u in self._queued_urls()),
        )

    def test_extracts_asp_string_literal(self):
        html = "url: '/asp/GetRandInfo.asp',"
        source = "http://192.168.100.1/index.asp"
        self.crawler._extract_links(html, source, 0)
        self.assertIn(
            "http://192.168.100.1/asp/GetRandInfo.asp", self._queued_urls(),
        )

    def test_extracts_form_action(self):
        html = '<form action="/login.cgi" method="POST"></form>'
        source = "http://192.168.100.1/index.asp"
        self.crawler._extract_links(html, source, 0)
        self.assertIn(
            "http://192.168.100.1/login.cgi", self._queued_urls(),
        )

    def test_extracts_document_write_src(self):
        html = """document.write('<script src="/resource/common/crypto-js.js"></script>');"""
        source = "http://192.168.100.1/index.asp"
        self.crawler._extract_links(html, source, 0)
        self.assertIn(
            "http://192.168.100.1/resource/common/crypto-js.js",
            self._queued_urls(),
        )

    def test_extracts_img_src_assignment(self):
        html = '''document.getElementById("imgcode").src = 'getCheckCode.cgi';'''
        source = "http://192.168.100.1/index.asp"
        self.crawler._extract_links(html, source, 0)
        self.assertTrue(
            any("getCheckCode.cgi" in u for u in self._queued_urls()),
        )

    def test_extracts_path_string_literal(self):
        html = '''var langSrc = "/frameaspdes/english/ssmpdes.js";'''
        source = "http://192.168.100.1/index.asp"
        self.crawler._extract_links(html, source, 0)
        self.assertIn(
            "http://192.168.100.1/frameaspdes/english/ssmpdes.js",
            self._queued_urls(),
        )

    def test_extracts_window_location(self):
        html = '''window.location = "/login.asp";'''
        source = "http://192.168.100.1/index.asp"
        self.crawler._extract_links(html, source, 0)
        self.assertIn(
            "http://192.168.100.1/login.asp", self._queued_urls(),
        )

    def test_ignores_data_urls(self):
        html = '<img src="data:image/png;base64,iVBOR" />'
        source = "http://192.168.100.1/index.asp"
        self.crawler._extract_links(html, source, 0)
        for u in self._queued_urls():
            self.assertNotIn("data:", u)

    def test_extracts_load_language(self):
        html = '''loadLanguage("langResource", "/frameaspdes/chinese/ssmpdes.js", cb);'''
        source = "http://192.168.100.1/index.asp"
        self.crawler._extract_links(html, source, 0)
        self.assertIn(
            "http://192.168.100.1/frameaspdes/chinese/ssmpdes.js",
            self._queued_urls(),
        )


class TestPasswordEncoding(unittest.TestCase):
    """Verify the Base64 password encoding matches router expectations."""

    def test_password_base64(self):
        password = "796cce597901a5cf"
        encoded = base64.b64encode(password.encode("utf-8")).decode("ascii")
        # The router JS uses base64encode(Password.value).
        self.assertEqual(encoded, "Nzk2Y2NlNTk3OTAxYTVjZg==")


class TestCookieLogging(unittest.TestCase):
    """Verify the cookie helper works."""

    def test_log_cookies_returns_dict(self):
        crawler = HuaweiCrawler(
            host="192.168.100.1",
            username="test",
            password="test",
            output_dir=tempfile.mkdtemp(),
            max_depth=0,
            delay=0,
        )
        crawler.session.cookies.set("TestCookie", "abc123", path="/")
        cookies = crawler._log_cookies("test")
        self.assertEqual(cookies, {"TestCookie": "abc123"})


class TestUnlimitedDepth(unittest.TestCase):
    """Verify that max_depth=0 means unlimited."""

    def test_zero_depth_is_unlimited(self):
        crawler = HuaweiCrawler(
            host="192.168.100.1",
            username="test",
            password="test",
            output_dir=tempfile.mkdtemp(),
            max_depth=0,
            delay=0,
        )
        # max_depth=0 should not reject items at any depth.
        # Internally the crawl loop checks: if self.max_depth and depth > self.max_depth
        # With max_depth=0, this is falsy and never triggers.
        self.assertFalse(crawler.max_depth)


class TestSkipExistingFiles(unittest.TestCase):
    """Verify that already-downloaded files are skipped."""

    def setUp(self):
        self.output_dir = tempfile.mkdtemp()
        self.crawler = HuaweiCrawler(
            host="192.168.100.1",
            username="test",
            password="test",
            output_dir=self.output_dir,
            max_depth=0,
            delay=0,
        )

    def test_scan_existing_populates_visited(self):
        # Create a fake existing file.
        sub = os.path.join(self.output_dir, "html", "status")
        os.makedirs(sub, exist_ok=True)
        with open(os.path.join(sub, "info.asp"), "w") as fh:
            fh.write("<html></html>")

        self.crawler._scan_existing_files()

        expected = "http://192.168.100.1/html/status/info.asp"
        self.assertIn(
            HuaweiCrawler._normalise_url(expected),
            self.crawler.visited,
        )

    def test_scan_existing_extracts_links(self):
        # Create a file with a link inside.
        sub = os.path.join(self.output_dir, "html")
        os.makedirs(sub, exist_ok=True)
        with open(os.path.join(sub, "page.asp"), "w") as fh:
            fh.write('<script src="/resource/common/util.js"></script>')

        self.crawler._scan_existing_files()

        urls = [u for u, _ in self.crawler.queue]
        self.assertIn("http://192.168.100.1/resource/common/util.js", urls)

    def test_scan_empty_dir_no_error(self):
        # Should not raise when output_dir does not exist.
        crawler = HuaweiCrawler(
            host="192.168.100.1",
            username="test",
            password="test",
            output_dir="/tmp/nonexistent_dir_" + str(os.getpid()),
            max_depth=0,
            delay=0,
        )
        crawler._scan_existing_files()  # should not raise
        self.assertEqual(len(crawler.visited), 0)

    def test_download_skips_existing_file(self):
        # Create a file that matches the URL path.
        os.makedirs(os.path.join(self.output_dir, "html"), exist_ok=True)
        filepath = os.path.join(self.output_dir, "html", "test.asp")
        with open(filepath, "w") as fh:
            fh.write("<html>cached</html>")

        # _download should return the cached content without HTTP.
        content = self.crawler._download("http://192.168.100.1/html/test.asp")
        self.assertIn("cached", content)


class TestSessionKeepAlive(unittest.TestCase):
    """Verify session keep-alive configuration."""

    def test_keepalive_interval_set(self):
        crawler = HuaweiCrawler(
            host="192.168.100.1",
            username="test",
            password="test",
            output_dir=tempfile.mkdtemp(),
            max_depth=0,
            delay=0,
        )
        self.assertEqual(crawler._keepalive_interval, 20)
        self.assertEqual(crawler._max_relogin_attempts, 3)
        self.assertEqual(crawler._max_consecutive_failures, 3)

    def test_response_is_login_redirect_url(self):
        """Detect redirect to login.asp in URL."""
        crawler = HuaweiCrawler(
            host="192.168.100.1",
            username="test",
            password="test",
            output_dir=tempfile.mkdtemp(),
            max_depth=0,
            delay=0,
        )

        class FakeResp:
            url = "http://192.168.100.1/login.asp"
            text = ""

        self.assertTrue(
            crawler._response_is_login_redirect(FakeResp(), "/html/status/info.asp"),
        )
        # Should NOT flag when original URL *is* login.asp.
        self.assertFalse(
            crawler._response_is_login_redirect(FakeResp(), "/login.asp"),
        )

    def test_response_is_login_redirect_body(self):
        """Detect login form in response body."""
        crawler = HuaweiCrawler(
            host="192.168.100.1",
            username="test",
            password="test",
            output_dir=tempfile.mkdtemp(),
            max_depth=0,
            delay=0,
        )

        class FakeResp:
            url = "http://192.168.100.1/html/status/info.asp"
            text = '<input id="txt_Username"> <form action="login.cgi">'

        self.assertTrue(
            crawler._response_is_login_redirect(FakeResp(), "/html/status/info.asp"),
        )


if __name__ == "__main__":
    unittest.main()
