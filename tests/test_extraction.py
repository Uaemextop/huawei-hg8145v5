"""
Tests for the link extraction module.
"""

import unittest

from web_crawler.extraction.links import extract_links
from web_crawler.extraction.css import extract_css_urls
from web_crawler.extraction.javascript import extract_js_paths
from web_crawler.extraction.json_extract import extract_json_paths


BASE = "https://example.com"
PAGE = "https://example.com/index.html"


class TestCssExtraction(unittest.TestCase):
    def test_url_function(self):
        css = "background: url('/images/bg.png');"
        result = extract_css_urls(css, PAGE, BASE)
        self.assertIn("https://example.com/images/bg.png", result)

    def test_import(self):
        css = '@import "/css/reset.css";'
        result = extract_css_urls(css, PAGE, BASE)
        self.assertIn("https://example.com/css/reset.css", result)


class TestJsExtraction(unittest.TestCase):
    def test_window_location(self):
        js = "window.location.href = '/about.html';"
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://example.com/about.html", result)

    def test_fetch_url(self):
        js = "fetch('/api/data.json');"
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://example.com/api/data.json", result)

    def test_ajax_url(self):
        js = "$.ajax({ url: '/api/users', type: 'GET' });"
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://example.com/api/users", result)


class TestJsonExtraction(unittest.TestCase):
    def test_json_path_value(self):
        data = '{"page": "/blog/post.html"}'
        result = extract_json_paths(data, PAGE, BASE)
        self.assertIn("https://example.com/blog/post.html", result)

    def test_invalid_json(self):
        result = extract_json_paths("not json", PAGE, BASE)
        self.assertEqual(len(result), 0)


class TestExtractLinks(unittest.TestCase):
    def test_html_extraction(self):
        html = '<a href="/about.html">About</a>'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://example.com/about.html", result)

    def test_css_extraction(self):
        css = "body { background: url('/images/bg.png'); }"
        result = extract_links(css, "text/css", PAGE, BASE)
        self.assertIn("https://example.com/images/bg.png", result)

    def test_js_extraction(self):
        js = "var page = '/blog/index.html';"
        result = extract_links(js, "application/javascript", PAGE, BASE)
        self.assertIn("https://example.com/blog/index.html", result)

    def test_html_with_multiple_links(self):
        html = """
        <html>
        <head>
            <link href="/css/style.css" rel="stylesheet">
            <script src="/js/main.js"></script>
        </head>
        <body>
            <a href="/about.html">About</a>
            <img src="/images/logo.png">
        </body>
        </html>
        """
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://example.com/css/style.css", result)
        self.assertIn("https://example.com/js/main.js", result)
        self.assertIn("https://example.com/about.html", result)
        self.assertIn("https://example.com/images/logo.png", result)


if __name__ == "__main__":
    unittest.main()
