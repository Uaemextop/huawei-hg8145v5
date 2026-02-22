"""
Tests for the link extraction module.
"""

import unittest

from huawei_crawler.extraction.links import extract_links
from huawei_crawler.extraction.css import extract_css_urls
from huawei_crawler.extraction.javascript import extract_js_paths
from huawei_crawler.extraction.json_extract import extract_json_paths


BASE = "http://192.168.100.1"
PAGE = "http://192.168.100.1/index.asp"


class TestCssExtraction(unittest.TestCase):
    def test_url_function(self):
        css = "background: url('/images/bg.png');"
        result = extract_css_urls(css, PAGE, BASE)
        self.assertIn("http://192.168.100.1/images/bg.png", result)

    def test_import(self):
        css = '@import "/Cuscss/english/frame.css";'
        result = extract_css_urls(css, PAGE, BASE)
        self.assertIn("http://192.168.100.1/Cuscss/english/frame.css", result)


class TestJsExtraction(unittest.TestCase):
    def test_window_location(self):
        js = "window.location.href = '/html/ssmp/wlan.asp';"
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("http://192.168.100.1/html/ssmp/wlan.asp", result)

    def test_set_action(self):
        js = "Form.setAction('/login.cgi');"
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("http://192.168.100.1/login.cgi", result)

    def test_ajax_url(self):
        js = "$.ajax({ url: '/asp/GetRandCount.asp', type: 'POST' });"
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("http://192.168.100.1/asp/GetRandCount.asp", result)

    def test_request_file(self):
        js = "Form.setAction('logout.cgi?RequestFile=html/logout.html');"
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("http://192.168.100.1/html/logout.html", result)


class TestJsonExtraction(unittest.TestCase):
    def test_json_path_value(self):
        data = '{"page": "/html/ssmp/home.asp"}'
        result = extract_json_paths(data, PAGE, BASE)
        self.assertIn("http://192.168.100.1/html/ssmp/home.asp", result)

    def test_invalid_json(self):
        result = extract_json_paths("not json", PAGE, BASE)
        self.assertEqual(len(result), 0)


class TestExtractLinks(unittest.TestCase):
    def test_html_extraction(self):
        html = '<a href="/html/ssmp/wlan.asp">WLAN</a>'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("http://192.168.100.1/html/ssmp/wlan.asp", result)

    def test_css_extraction(self):
        css = "body { background: url('/images/bg.png'); }"
        result = extract_links(css, "text/css", PAGE, BASE)
        self.assertIn("http://192.168.100.1/images/bg.png", result)

    def test_js_extraction(self):
        js = "var page = '/html/ssmp/home.asp';"
        result = extract_links(js, "application/javascript", PAGE, BASE)
        self.assertIn("http://192.168.100.1/html/ssmp/home.asp", result)

    def test_asp_treated_as_html(self):
        """ASP responses should be treated as HTML regardless of Content-Type."""
        asp_content = '<script>window.location = "/admin.asp";</script>'
        result = extract_links(
            asp_content, "text/html",
            "http://192.168.100.1/page.asp", BASE
        )
        self.assertIn("http://192.168.100.1/admin.asp", result)


if __name__ == "__main__":
    unittest.main()
