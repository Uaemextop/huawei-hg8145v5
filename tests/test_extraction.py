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


class TestHiddenFileExtraction(unittest.TestCase):
    """Test that hidden/config file references are extracted from JS/HTML."""

    def test_js_env_path(self):
        js = 'var config = "/.env";'
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://example.com/.env", result)

    def test_js_htaccess_path(self):
        js = 'var path = "/.htaccess";'
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://example.com/.htaccess", result)

    def test_js_config_path(self):
        js = 'var f = "/app/.config";'
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://example.com/app/.config", result)

    def test_js_cfg_path(self):
        js = 'var f = "/settings.cfg";'
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://example.com/settings.cfg", result)

    def test_js_hst_path(self):
        js = 'var f = "/data/history.hst";'
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://example.com/data/history.hst", result)

    def test_js_env_local_path(self):
        js = 'var f = "/.env.local";'
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://example.com/.env.local", result)

    def test_js_gitignore_path(self):
        js = 'var f = "/.gitignore";'
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://example.com/.gitignore", result)

    def test_hidden_file_in_html_link(self):
        html = '<a href="/.env">env</a>'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://example.com/.env", result)

    def test_hidden_file_in_html_script(self):
        html = '<script>var x = "/config.ini";</script>'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://example.com/config.ini", result)


class TestHiddenFileProbeConfig(unittest.TestCase):
    """Test that the probe list is properly configured."""

    def test_probe_list_not_empty(self):
        from web_crawler.config import HIDDEN_FILE_PROBES
        self.assertGreater(len(HIDDEN_FILE_PROBES), 0)

    def test_probe_list_contains_env(self):
        from web_crawler.config import HIDDEN_FILE_PROBES
        self.assertIn(".env", HIDDEN_FILE_PROBES)

    def test_probe_list_contains_htaccess(self):
        from web_crawler.config import HIDDEN_FILE_PROBES
        self.assertIn(".htaccess", HIDDEN_FILE_PROBES)

    def test_probe_list_contains_cfg(self):
        from web_crawler.config import HIDDEN_FILE_PROBES
        self.assertIn(".cfg", HIDDEN_FILE_PROBES)

    def test_probe_list_contains_hst(self):
        from web_crawler.config import HIDDEN_FILE_PROBES
        self.assertIn(".hst", HIDDEN_FILE_PROBES)

    def test_probe_list_contains_config(self):
        from web_crawler.config import HIDDEN_FILE_PROBES
        self.assertIn(".config", HIDDEN_FILE_PROBES)


if __name__ == "__main__":
    unittest.main()
