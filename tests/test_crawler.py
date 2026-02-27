"""
Tests for crawler soft-404 detection, WordPress detection, WAF/protection
detection, header retry, and JSON extraction.
"""

import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from web_crawler.config import (
    SOFT_404_KEYWORDS,
    SOFT_404_SIZE_RATIO,
    USER_AGENTS,
    WAF_SIGNATURES,
    WP_DISCOVERY_PATHS,
    WP_PLUGIN_PROBES,
    WP_THEME_PROBES,
    HEADER_RETRY_MAX,
    RETRY_STATUS_CODES,
)
from web_crawler.core.crawler import Crawler
from web_crawler.core.storage import content_hash
from web_crawler.extraction.json_extract import extract_json_paths
from web_crawler.session import random_headers


BASE = "https://example.com"
PAGE = "https://example.com/index.html"


# ------------------------------------------------------------------ #
# Soft-404 detection
# ------------------------------------------------------------------ #

class TestSoft404Detection(unittest.TestCase):
    """Test the soft-404 (false positive) detection logic."""

    def _make_crawler(self):
        with patch.object(Crawler, "_load_robots"):
            crawler = Crawler(
                start_url="https://example.com",
                output_dir=Path("/tmp/test_crawl_output"),
                respect_robots=False,
            )
        return crawler

    def test_exact_hash_match_is_soft_404(self):
        crawler = self._make_crawler()
        body = b"<html><body><h1>Page not found</h1></body></html>"
        crawler._soft404_hash = content_hash(body)
        crawler._soft404_size = len(body)
        self.assertTrue(crawler._is_soft_404(body, "https://example.com/missing"))

    def test_different_content_not_soft_404(self):
        crawler = self._make_crawler()
        baseline = b"<html><body><h1>Page not found</h1></body></html>"
        crawler._soft404_hash = content_hash(baseline)
        crawler._soft404_size = len(baseline)
        real_page = b"<html><body><h1>Welcome to our site!</h1><p>Real content here.</p></body></html>"
        self.assertFalse(crawler._is_soft_404(real_page, "https://example.com/real"))

    def test_similar_size_with_keywords_is_soft_404(self):
        crawler = self._make_crawler()
        baseline = b"<html><body><h1>Error 404</h1><p>Page not found.</p></body></html>"
        crawler._soft404_hash = content_hash(baseline)
        crawler._soft404_size = len(baseline)
        # Similar size, different hash, but has 404 keywords
        variant = b"<html><body><h1>Error 404</h1><p>Page not found!</p></body></html>"
        self.assertTrue(crawler._is_soft_404(variant, "https://example.com/gone"))

    def test_similar_size_without_keywords_not_soft_404(self):
        crawler = self._make_crawler()
        baseline = b"<html><body><h1>Error 404</h1><p>Page not found.</p></body></html>"
        crawler._soft404_hash = content_hash(baseline)
        crawler._soft404_size = len(baseline)
        # Same size range but no 404 keywords
        no_kw = b"<html><body><h1>Hi there</h1><p>Welcome to my page</p></body></html>"
        self.assertFalse(crawler._is_soft_404(no_kw, "https://example.com/ok"))

    def test_no_baseline_disables_detection(self):
        crawler = self._make_crawler()
        # No fingerprint built
        body = b"<html><body><h1>Page not found</h1></body></html>"
        self.assertFalse(crawler._is_soft_404(body, "https://example.com/x"))

    def test_soft404_keywords_config(self):
        self.assertIn("page not found", SOFT_404_KEYWORDS)
        self.assertIn("404", SOFT_404_KEYWORDS)
        self.assertIn("not found", SOFT_404_KEYWORDS)
        self.assertIn("no encontrado", SOFT_404_KEYWORDS)

    def test_soft404_size_ratio_config(self):
        self.assertIsInstance(SOFT_404_SIZE_RATIO, float)
        self.assertGreater(SOFT_404_SIZE_RATIO, 0)
        self.assertLess(SOFT_404_SIZE_RATIO, 1)


# ------------------------------------------------------------------ #
# WordPress detection
# ------------------------------------------------------------------ #

class TestWordPressDetection(unittest.TestCase):
    """Test the WordPress site detection logic."""

    def test_detect_wp_content(self):
        html = '<link rel="stylesheet" href="/wp-content/themes/flavor/style.css">'
        self.assertTrue(Crawler.detect_wordpress(html))

    def test_detect_wp_includes(self):
        html = '<script src="/wp-includes/js/jquery/jquery.min.js"></script>'
        self.assertTrue(Crawler.detect_wordpress(html))

    def test_detect_wp_generator_meta(self):
        html = '<meta name="generator" content="WordPress 6.4.2">'
        self.assertTrue(Crawler.detect_wordpress(html))

    def test_detect_wp_json_link(self):
        html = '<link rel="https://api.w.org/" href="https://example.com/wp-json/">'
        self.assertTrue(Crawler.detect_wordpress(html))

    def test_detect_wp_emoji(self):
        html = '<script src="/wp-includes/js/wp-emoji-release.min.js"></script>'
        self.assertTrue(Crawler.detect_wordpress(html))

    def test_non_wp_site(self):
        html = '<html><head><title>My Site</title></head><body>Hello</body></html>'
        self.assertFalse(Crawler.detect_wordpress(html))

    def test_wp_discovery_paths_config(self):
        self.assertIn("/wp-json/", WP_DISCOVERY_PATHS)
        self.assertIn("/wp-json/wp/v2/posts", WP_DISCOVERY_PATHS)
        self.assertIn("/wp-json/wp/v2/users", WP_DISCOVERY_PATHS)
        self.assertIn("/wp-sitemap.xml", WP_DISCOVERY_PATHS)
        self.assertIn("/feed/", WP_DISCOVERY_PATHS)

    def test_wp_plugin_probes_not_empty(self):
        self.assertGreater(len(WP_PLUGIN_PROBES), 20)
        self.assertIn("wordfence", WP_PLUGIN_PROBES)
        self.assertIn("woocommerce", WP_PLUGIN_PROBES)
        self.assertIn("akismet", WP_PLUGIN_PROBES)

    def test_wp_theme_probes_not_empty(self):
        self.assertGreater(len(WP_THEME_PROBES), 5)
        self.assertIn("twentytwentyfive", WP_THEME_PROBES)
        self.assertIn("astra", WP_THEME_PROBES)


# ------------------------------------------------------------------ #
# WAF / Cloudflare / CAPTCHA detection
# ------------------------------------------------------------------ #

class TestWAFDetection(unittest.TestCase):
    """Test WAF / Cloudflare / CAPTCHA detection."""

    def test_detect_cloudflare_header(self):
        headers = {"CF-RAY": "abc123", "Server": "cloudflare"}
        result = Crawler.detect_protection(headers, "")
        self.assertIn("cloudflare", result)

    def test_detect_cloudflare_body(self):
        headers = {}
        body = '<title>Attention Required! | Cloudflare</title>'
        result = Crawler.detect_protection(headers, body)
        self.assertIn("cloudflare", result)

    def test_detect_wordfence(self):
        headers = {}
        body = 'This site is protected by Wordfence'
        result = Crawler.detect_protection(headers, body)
        self.assertIn("wordfence", result)

    def test_detect_sucuri(self):
        headers = {"X-Sucuri-ID": "12345"}
        result = Crawler.detect_protection(headers, "")
        self.assertIn("sucuri", result)

    def test_detect_captcha(self):
        headers = {}
        body = '<div class="g-recaptcha" data-sitekey="xyz"></div>'
        result = Crawler.detect_protection(headers, body)
        self.assertIn("captcha", result)

    def test_detect_hcaptcha(self):
        headers = {}
        body = '<div class="h-captcha" data-sitekey="xyz"></div>'
        result = Crawler.detect_protection(headers, body)
        self.assertIn("captcha", result)

    def test_detect_turnstile(self):
        headers = {}
        body = '<div class="cf-turnstile" data-sitekey="xyz"></div>'
        result = Crawler.detect_protection(headers, body)
        self.assertIn("captcha", result)

    def test_detect_imperva(self):
        headers = {"X-Iinfo": "1-2-3"}
        result = Crawler.detect_protection(headers, "")
        self.assertIn("imperva", result)

    def test_detect_modsecurity(self):
        headers = {"Server": "Apache/ModSecurity"}
        result = Crawler.detect_protection(headers, "")
        self.assertIn("modsecurity", result)

    def test_no_protection_detected(self):
        headers = {"Server": "nginx"}
        body = '<html><body>Hello</body></html>'
        result = Crawler.detect_protection(headers, body)
        self.assertEqual(result, [])

    def test_multiple_protections(self):
        headers = {"CF-RAY": "abc"}
        body = '<div class="g-recaptcha"></div>'
        result = Crawler.detect_protection(headers, body)
        self.assertIn("cloudflare", result)
        self.assertIn("captcha", result)

    def test_waf_signatures_config(self):
        self.assertIn("cloudflare", WAF_SIGNATURES)
        self.assertIn("wordfence", WAF_SIGNATURES)
        self.assertIn("sucuri", WAF_SIGNATURES)
        self.assertIn("captcha", WAF_SIGNATURES)
        self.assertIn("imperva", WAF_SIGNATURES)
        self.assertIn("modsecurity", WAF_SIGNATURES)
        self.assertIn("akamai", WAF_SIGNATURES)


# ------------------------------------------------------------------ #
# User-Agent rotation and header retry
# ------------------------------------------------------------------ #

class TestHeaderRotation(unittest.TestCase):
    """Test User-Agent pool and header rotation."""

    def test_user_agents_pool_not_empty(self):
        self.assertGreater(len(USER_AGENTS), 5)

    def test_user_agents_all_strings(self):
        for ua in USER_AGENTS:
            self.assertIsInstance(ua, str)
            self.assertGreater(len(ua), 20)

    def test_user_agents_diverse(self):
        """Pool should contain multiple browser families."""
        all_uas = " ".join(USER_AGENTS).lower()
        self.assertIn("chrome", all_uas)
        self.assertIn("firefox", all_uas)
        self.assertIn("safari", all_uas)

    def test_random_headers_returns_dict(self):
        hdrs = random_headers("https://example.com")
        self.assertIsInstance(hdrs, dict)
        self.assertIn("User-Agent", hdrs)
        self.assertIn("Accept", hdrs)
        self.assertIn("Accept-Language", hdrs)

    def test_random_headers_with_referer(self):
        hdrs = random_headers("https://example.com")
        self.assertEqual(hdrs["Referer"], "https://example.com")
        self.assertEqual(hdrs["Origin"], "https://example.com")

    def test_retry_status_codes_config(self):
        self.assertIn(403, RETRY_STATUS_CODES)
        self.assertIn(402, RETRY_STATUS_CODES)

    def test_header_retry_max_config(self):
        self.assertGreater(HEADER_RETRY_MAX, 0)


# ------------------------------------------------------------------ #
# JSON extraction – full URL support for WordPress REST API
# ------------------------------------------------------------------ #

class TestJsonFullUrlExtraction(unittest.TestCase):
    """Test that JSON extractor handles full http(s) URLs (WP REST API)."""

    def test_absolute_url_same_host(self):
        data = '{"link": "https://example.com/blog/my-post/"}'
        result = extract_json_paths(data, PAGE, BASE)
        self.assertIn("https://example.com/blog/my-post/", result)

    def test_absolute_url_external_rejected(self):
        data = '{"link": "https://evil.com/steal"}'
        result = extract_json_paths(data, PAGE, BASE)
        self.assertNotIn("https://evil.com/steal", result)

    def test_wp_rest_api_response(self):
        data = '''[
            {"id": 1, "link": "https://example.com/hello-world/",
             "title": {"rendered": "Hello world!"}},
            {"id": 2, "link": "https://example.com/sample-page/",
             "title": {"rendered": "Sample Page"}}
        ]'''
        result = extract_json_paths(data, PAGE, BASE)
        self.assertIn("https://example.com/hello-world/", result)
        self.assertIn("https://example.com/sample-page/", result)

    def test_path_still_extracted(self):
        data = '{"page": "/blog/post.html"}'
        result = extract_json_paths(data, PAGE, BASE)
        self.assertIn("https://example.com/blog/post.html", result)

    def test_http_prefix_no_false_match(self):
        """Strings like 'httponly' should not be treated as URLs."""
        data = '{"flag": "httponly", "attr": "httprequest"}'
        result = extract_json_paths(data, PAGE, BASE)
        self.assertEqual(len(result), 0)


if __name__ == "__main__":
    unittest.main()
