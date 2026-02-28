"""
Tests for crawler soft-404 detection, WordPress detection, WAF/protection
detection, header retry, cache bypass, deep WP crawl, and JSON extraction.
"""

import logging
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from web_crawler.config import (
    SOFT_404_KEYWORDS,
    SOFT_404_SIZE_RATIO,
    SOFT_404_STANDALONE_MIN_HITS,
    SOFT_404_TITLE_KEYWORDS,
    USER_AGENTS,
    WAF_SIGNATURES,
    WP_DISCOVERY_PATHS,
    WP_PLUGIN_FILES,
    WP_PLUGIN_PROBES,
    WP_THEME_FILES,
    WP_THEME_PROBES,
    HEADER_RETRY_MAX,
    RETRY_STATUS_CODES,
)
from web_crawler.core.crawler import Crawler
from web_crawler.core.storage import content_hash
from web_crawler.extraction.json_extract import extract_json_paths
from web_crawler.session import random_headers, cache_bust_url


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

    def test_no_baseline_standalone_detection(self):
        """Standalone keyword detection works even without baseline."""
        crawler = self._make_crawler()
        # No fingerprint built – but body has multiple 404 keywords
        body = b"<html><body><h1>Page not found</h1></body></html>"
        self.assertTrue(crawler._is_soft_404(body, "https://example.com/x"))

    def test_no_baseline_single_keyword_not_detected(self):
        """A single keyword hit is not enough for standalone detection."""
        crawler = self._make_crawler()
        # Only one keyword ("oops") – below SOFT_404_STANDALONE_MIN_HITS
        body = b"<html><body><h1>Oops</h1><p>Something went wrong.</p></body></html>"
        self.assertFalse(crawler._is_soft_404(body, "https://example.com/x"))

    def test_title_based_soft_404(self):
        """Detection by <title> tag containing 404-like keywords."""
        crawler = self._make_crawler()
        body = b"<html><head><title>Error 404</title></head><body><p>Welcome to our site</p></body></html>"
        self.assertTrue(crawler._is_soft_404(body, "https://example.com/missing"))

    def test_title_without_404_not_detected(self):
        """A normal <title> does not trigger soft-404."""
        crawler = self._make_crawler()
        body = b"<html><head><title>Welcome</title></head><body><p>Hello world</p></body></html>"
        self.assertFalse(crawler._is_soft_404(body, "https://example.com/ok"))

    def test_spanish_soft_404_standalone(self):
        """Standalone detection with Spanish keywords."""
        crawler = self._make_crawler()
        body = b"<html><body><h1>Pagina no encontrada</h1><p>Lo sentimos</p></body></html>"
        self.assertTrue(crawler._is_soft_404(body, "https://example.com/es/missing"))

    def test_soft404_keywords_config(self):
        self.assertIn("page not found", SOFT_404_KEYWORDS)
        self.assertIn("404", SOFT_404_KEYWORDS)
        self.assertIn("not found", SOFT_404_KEYWORDS)
        self.assertIn("no encontrado", SOFT_404_KEYWORDS)

    def test_soft404_size_ratio_config(self):
        self.assertIsInstance(SOFT_404_SIZE_RATIO, float)
        self.assertGreater(SOFT_404_SIZE_RATIO, 0)
        self.assertLess(SOFT_404_SIZE_RATIO, 1)

    def test_soft404_title_keywords_config(self):
        self.assertIn("404", SOFT_404_TITLE_KEYWORDS)
        self.assertIn("not found", SOFT_404_TITLE_KEYWORDS)
        self.assertIn("no encontrada", SOFT_404_TITLE_KEYWORDS)

    def test_soft404_standalone_min_hits_config(self):
        self.assertIsInstance(SOFT_404_STANDALONE_MIN_HITS, int)
        self.assertGreaterEqual(SOFT_404_STANDALONE_MIN_HITS, 2)


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
# --no-check-captcha flag (skip_captcha_check)
# ------------------------------------------------------------------ #

class TestSkipCaptchaCheck(unittest.TestCase):
    """Test that skip_captcha_check disables protection detection."""

    def _make_crawler(self, skip: bool = False) -> Crawler:
        return Crawler(
            start_url="https://example.com",
            output_dir=Path("/tmp/test_skip_captcha"),
            skip_captcha_check=skip,
        )

    def test_default_captcha_check_enabled(self):
        c = self._make_crawler(skip=False)
        self.assertFalse(c.skip_captcha_check)

    def test_captcha_check_disabled(self):
        c = self._make_crawler(skip=True)
        self.assertTrue(c.skip_captcha_check)

    def test_detect_protection_still_works(self):
        """detect_protection() itself is unaffected by the flag."""
        body = '<div class="g-recaptcha"></div>'
        result = Crawler.detect_protection({}, body)
        self.assertIn("captcha", result)


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


# ------------------------------------------------------------------ #
# Cache-busting
# ------------------------------------------------------------------ #

class TestCacheBusting(unittest.TestCase):
    """Test cache-bust URL generation."""

    def test_cache_bust_adds_param(self):
        url = "https://example.com/page.html"
        busted = cache_bust_url(url)
        self.assertIn("_cb=", busted)
        self.assertTrue(busted.startswith("https://example.com/page.html?"))

    def test_cache_bust_preserves_query(self):
        url = "https://example.com/search?q=test"
        busted = cache_bust_url(url)
        self.assertIn("q=test", busted)
        self.assertIn("&_cb=", busted)

    def test_cache_bust_random_value(self):
        url = "https://example.com/"
        bust1 = cache_bust_url(url)
        bust2 = cache_bust_url(url)
        # They should differ (extremely unlikely to be the same)
        # Just check both have the parameter
        self.assertIn("_cb=", bust1)
        self.assertIn("_cb=", bust2)

    def test_random_headers_has_cache_control(self):
        hdrs = random_headers("https://example.com")
        self.assertIn("Cache-Control", hdrs)
        self.assertIn("Pragma", hdrs)
        self.assertEqual(hdrs["Pragma"], "no-cache")


# ------------------------------------------------------------------ #
# Deep WP plugin/theme crawl config
# ------------------------------------------------------------------ #

class TestDeepWPCrawlConfig(unittest.TestCase):
    """Test WP plugin/theme internal file lists."""

    def test_plugin_files_not_empty(self):
        self.assertGreater(len(WP_PLUGIN_FILES), 5)

    def test_plugin_files_contains_readme(self):
        self.assertIn("readme.txt", WP_PLUGIN_FILES)

    def test_plugin_files_contains_composer(self):
        self.assertIn("composer.json", WP_PLUGIN_FILES)

    def test_plugin_files_contains_debug_log(self):
        self.assertIn("debug.log", WP_PLUGIN_FILES)

    def test_theme_files_not_empty(self):
        self.assertGreater(len(WP_THEME_FILES), 10)

    def test_theme_files_contains_style_css(self):
        self.assertIn("style.css", WP_THEME_FILES)

    def test_theme_files_contains_functions_php(self):
        self.assertIn("functions.php", WP_THEME_FILES)

    def test_theme_files_contains_header_php(self):
        self.assertIn("header.php", WP_THEME_FILES)

    def test_theme_files_contains_footer_php(self):
        self.assertIn("footer.php", WP_THEME_FILES)

    def test_theme_files_contains_screenshot(self):
        self.assertIn("screenshot.png", WP_THEME_FILES)

    def test_theme_files_contains_theme_json(self):
        self.assertIn("theme.json", WP_THEME_FILES)


# ------------------------------------------------------------------ #
# Deep WP crawl logic
# ------------------------------------------------------------------ #

class TestDeepWPCrawl(unittest.TestCase):
    """Test that confirmed plugins/themes trigger deep crawl."""

    def _make_crawler(self):
        with patch.object(Crawler, "_load_robots"):
            crawler = Crawler(
                start_url="https://example.com",
                output_dir=Path("/tmp/test_crawl_output"),
                respect_robots=False,
            )
        return crawler

    def test_deep_crawl_plugin(self):
        crawler = self._make_crawler()
        crawler._wp_detected = True
        crawler._deep_crawl_wp_plugin("wordfence", 0)
        self.assertIn("wordfence", crawler._wp_confirmed_plugins)
        # Check that internal files were enqueued
        queued = {url for url, _ in crawler._queue}
        self.assertTrue(
            any("/wp-content/plugins/wordfence/readme.txt" in u for u in queued)
        )
        self.assertTrue(
            any("/wp-content/plugins/wordfence/composer.json" in u for u in queued)
        )

    def test_deep_crawl_theme(self):
        crawler = self._make_crawler()
        crawler._wp_detected = True
        crawler._deep_crawl_wp_theme("flavor", 0)
        self.assertIn("flavor", crawler._wp_confirmed_themes)
        queued = {url for url, _ in crawler._queue}
        self.assertTrue(
            any("/wp-content/themes/flavor/functions.php" in u for u in queued)
        )
        self.assertTrue(
            any("/wp-content/themes/flavor/style.css" in u for u in queued)
        )

    def test_deep_crawl_not_duplicated(self):
        crawler = self._make_crawler()
        crawler._wp_detected = True
        crawler._deep_crawl_wp_plugin("wordfence", 0)
        q_size = len(crawler._queue)
        crawler._deep_crawl_wp_plugin("wordfence", 0)
        self.assertEqual(len(crawler._queue), q_size)

    def test_check_wp_deep_crawl_plugin_path(self):
        crawler = self._make_crawler()
        crawler._wp_detected = True
        crawler._check_wp_deep_crawl(
            "/wp-content/plugins/akismet/readme.txt", 0
        )
        self.assertIn("akismet", crawler._wp_confirmed_plugins)

    def test_check_wp_deep_crawl_theme_path(self):
        crawler = self._make_crawler()
        crawler._wp_detected = True
        crawler._check_wp_deep_crawl(
            "/wp-content/themes/flavor/style.css", 0
        )
        self.assertIn("flavor", crawler._wp_confirmed_themes)

    def test_wp_nonce_extraction(self):
        crawler = self._make_crawler()
        crawler._wp_detected = True
        html = '''<script>var wpApiSettings = {"nonce":"abc123def","root":"https:\\/\\/example.com\\/wp-json\\/"};</script>'''
        crawler._extract_wp_nonce(html)
        self.assertEqual(crawler.session.headers.get("X-WP-Nonce"), "abc123def")


# ------------------------------------------------------------------ #
# Git push integration
# ------------------------------------------------------------------ #

class TestGitPushIntegration(unittest.TestCase):
    """Test the periodic git push feature."""

    def _make_crawler(self, git_push_every=0):
        with patch.object(Crawler, "_load_robots"):
            crawler = Crawler(
                start_url="https://example.com",
                output_dir=Path("/tmp/test_crawl_output"),
                respect_robots=False,
                git_push_every=git_push_every,
            )
        return crawler

    def test_git_push_disabled_by_default(self):
        crawler = self._make_crawler()
        self.assertEqual(crawler.git_push_every, 0)
        # Should not attempt any subprocess calls
        crawler._stats["ok"] = 100
        crawler._maybe_git_push()  # no error, does nothing

    def test_git_push_not_triggered_below_threshold(self):
        crawler = self._make_crawler(git_push_every=100)
        crawler._stats["ok"] = 50
        with patch("subprocess.run") as mock_run:
            crawler._maybe_git_push()
            mock_run.assert_not_called()

    def test_git_push_triggered_at_threshold(self):
        crawler = self._make_crawler(git_push_every=100)
        crawler._stats["ok"] = 100
        with patch("subprocess.run") as mock_run:
            crawler._maybe_git_push()
            self.assertEqual(mock_run.call_count, 3)  # add, commit, push

    def test_git_push_triggered_at_multiple(self):
        crawler = self._make_crawler(git_push_every=100)
        crawler._stats["ok"] = 200
        with patch("subprocess.run") as mock_run:
            crawler._maybe_git_push()
            self.assertEqual(mock_run.call_count, 3)

    def test_git_push_not_triggered_off_multiple(self):
        crawler = self._make_crawler(git_push_every=100)
        crawler._stats["ok"] = 150
        with patch("subprocess.run") as mock_run:
            crawler._maybe_git_push()
            mock_run.assert_not_called()

    def test_git_not_found_disables_feature(self):
        crawler = self._make_crawler(git_push_every=100)
        crawler._stats["ok"] = 100
        with patch("subprocess.run", side_effect=FileNotFoundError):
            crawler._maybe_git_push()
        self.assertEqual(crawler.git_push_every, 0)


# ------------------------------------------------------------------ #
# Logging system
# ------------------------------------------------------------------ #

class TestLogging(unittest.TestCase):
    """Test the logging configuration."""

    @staticmethod
    def _cleanup_log(logger):
        """Close and remove all handlers to avoid ResourceWarning."""
        for h in list(logger.handlers):
            h.close()
            logger.removeHandler(h)

    def test_setup_logging_creates_handler(self):
        from web_crawler.utils.log import setup_logging, log as _log
        setup_logging(debug=False)
        self.assertGreater(len(_log.handlers), 0)
        self._cleanup_log(_log)

    def test_setup_logging_debug_level(self):
        from web_crawler.utils.log import setup_logging, log as _log
        setup_logging(debug=True)
        self.assertEqual(_log.level, logging.DEBUG)
        self._cleanup_log(_log)

    def test_setup_logging_info_level(self):
        from web_crawler.utils.log import setup_logging, log as _log
        setup_logging(debug=False)
        self.assertEqual(_log.level, logging.INFO)
        self._cleanup_log(_log)

    def test_setup_logging_with_file(self):
        import os
        import tempfile
        from web_crawler.utils.log import setup_logging, log as _log
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "test.log")
            setup_logging(debug=False, log_file=log_path)
            _log.info("test message for file logging")
            for h in _log.handlers:
                h.flush()
            self.assertTrue(os.path.exists(log_path))
            with open(log_path) as f:
                content = f.read()
            self.assertIn("test message for file logging", content)
            self._cleanup_log(_log)

    def test_file_log_always_debug_level(self):
        """File handler should always capture DEBUG-level messages."""
        import os
        import tempfile
        from web_crawler.utils.log import setup_logging, log as _log
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "test_debug.log")
            setup_logging(debug=False, log_file=log_path)
            _log.setLevel(logging.DEBUG)
            _log.debug("debug detail for file")
            for h in _log.handlers:
                h.flush()
            with open(log_path) as f:
                content = f.read()
            self.assertIn("debug detail for file", content)
            self._cleanup_log(_log)


    def test_category_formatter_highlights_tags(self):
        """_CategoryFormatter should inject ANSI codes for known tags."""
        from web_crawler.utils.log import _CategoryFormatter, _CATEGORY_STYLES, _ANSI_RESET
        formatter = _CategoryFormatter("%(message)s")
        record = logging.LogRecord(
            name="test", level=logging.WARNING, pathname="", lineno=0,
            msg="  [PROTECTION] captcha on https://example.com – not saving",
            args=(), exc_info=None,
        )
        output = formatter.format(record)
        style = _CATEGORY_STYLES["[PROTECTION]"]
        self.assertIn(f"{style}[PROTECTION]{_ANSI_RESET}", output)

    def test_category_formatter_no_tag(self):
        """Messages without known tags pass through unchanged."""
        from web_crawler.utils.log import _CategoryFormatter
        formatter = _CategoryFormatter("%(message)s")
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="simple message", args=(), exc_info=None,
        )
        output = formatter.format(record)
        self.assertEqual(output, "simple message")


# ------------------------------------------------------------------ #
# SiteGround CAPTCHA (PoW) solver
# ------------------------------------------------------------------ #

class TestSGCaptchaSolver(unittest.TestCase):
    """Tests for the SiteGround Proof-of-Work captcha solver."""

    def test_solve_sg_pow_basic(self):
        """solve_sg_pow returns a valid base64 solution."""
        from web_crawler.session import solve_sg_pow
        result = solve_sg_pow("20:1234567890:aabbccdd:deadbeef:")
        self.assertIsNotNone(result)
        sol, counter = result
        self.assertIsInstance(sol, str)
        self.assertGreater(counter, 0)

    def test_solve_sg_pow_verifies_leading_zeros(self):
        """Solution actually has the required leading zero bits."""
        import hashlib, struct, base64
        from web_crawler.session import solve_sg_pow
        challenge = "16:9999999:abcdef12:0123456789abcdef:"
        result = solve_sg_pow(challenge)
        self.assertIsNotNone(result)
        sol, _ = result
        data = base64.b64decode(sol)
        h = hashlib.sha1(data).digest()
        first_word = struct.unpack(">I", h[:4])[0]
        self.assertEqual(first_word >> (32 - 16), 0)

    def test_solve_sg_pow_invalid_challenge(self):
        """Invalid challenge returns None."""
        from web_crawler.session import solve_sg_pow
        self.assertIsNone(solve_sg_pow(""))
        self.assertIsNone(solve_sg_pow("notanumber:x:y:z:"))
        self.assertIsNone(solve_sg_pow("99:x:y:z:"))

    def test_is_sg_captcha_response_header(self):
        """Detect SG-Captcha via header."""
        from web_crawler.session import is_sg_captcha_response
        resp = MagicMock()
        resp.headers = {"SG-Captcha": "challenge"}
        resp.status_code = 202
        resp.text = ""
        self.assertTrue(is_sg_captcha_response(resp))

    def test_is_sg_captcha_response_body(self):
        """Detect SG-Captcha via body meta refresh."""
        from web_crawler.session import is_sg_captcha_response
        resp = MagicMock()
        resp.headers = {}
        resp.status_code = 202
        resp.text = '<html><meta http-equiv="refresh" content="0;/.well-known/sgcaptcha/?r=%2F.env"></html>'
        self.assertTrue(is_sg_captcha_response(resp))

    def test_not_sg_captcha_normal_200(self):
        """Normal 200 page is not detected as captcha."""
        from web_crawler.session import is_sg_captcha_response
        resp = MagicMock()
        resp.headers = {}
        resp.status_code = 200
        resp.text = "<html><body>Hello</body></html>"
        self.assertFalse(is_sg_captcha_response(resp))

    def test_counter_to_bytes(self):
        """counter_to_bytes encodes correctly."""
        from web_crawler.session import _counter_to_bytes
        self.assertEqual(_counter_to_bytes(0), b"\x00")
        self.assertEqual(_counter_to_bytes(1), b"\x01")
        self.assertEqual(_counter_to_bytes(255), b"\xff")
        self.assertEqual(_counter_to_bytes(256), b"\x01\x00")
        self.assertEqual(_counter_to_bytes(65536), b"\x01\x00\x00")
        self.assertEqual(_counter_to_bytes(16777216), b"\x01\x00\x00\x00")


# ------------------------------------------------------------------ #
# Probe 403 threshold / adaptive disabling
# ------------------------------------------------------------------ #

class TestProbe403Threshold(unittest.TestCase):
    """Tests for the adaptive probe disabling on consecutive 403 errors."""

    def _make_crawler(self):
        with patch.object(Crawler, "_load_robots"):
            crawler = Crawler(
                start_url="https://example.com",
                output_dir=Path("/tmp/test_crawl_output"),
                respect_robots=False,
            )
        return crawler

    def test_probe_urls_are_tracked(self):
        """_probe_hidden_files populates _probe_urls."""
        crawler = self._make_crawler()
        crawler._probe_hidden_files("https://example.com/page.html", 0)
        self.assertGreater(len(crawler._probe_urls), 0)

    def test_probing_disabled_after_threshold(self):
        """After PROBE_403_THRESHOLD 403s, probing is disabled."""
        from web_crawler.config import PROBE_403_THRESHOLD
        crawler = self._make_crawler()
        crawler._probe_403_count = PROBE_403_THRESHOLD
        crawler._probing_disabled = True
        # After disabling, _probe_hidden_files should not enqueue
        prev_queue = len(crawler._queue)
        crawler._probe_hidden_files("https://example.com/new/", 0)
        self.assertEqual(len(crawler._queue), prev_queue)

    def test_probing_not_disabled_below_threshold(self):
        """Below threshold, probing still works."""
        crawler = self._make_crawler()
        crawler._probe_403_count = 5
        crawler._probe_hidden_files("https://example.com/dir/", 0)
        self.assertGreater(len(crawler._queue), 0)

    def test_probe_dir_dedup(self):
        """Same directory is not probed twice."""
        crawler = self._make_crawler()
        crawler._probe_hidden_files("https://example.com/a/page.html", 0)
        q1 = len(crawler._queue)
        crawler._probe_hidden_files("https://example.com/a/other.html", 0)
        self.assertEqual(len(crawler._queue), q1)


# ------------------------------------------------------------------ #
# WAF signatures include SiteGround
# ------------------------------------------------------------------ #

class TestSiteGroundWAFSignature(unittest.TestCase):
    """Tests for SiteGround WAF detection signatures."""

    def test_siteground_in_waf_signatures(self):
        self.assertIn("siteground", WAF_SIGNATURES)

    def test_siteground_detects_sg_captcha_header(self):
        headers = {"SG-Captcha": "challenge", "Server": "nginx"}
        body = ""
        result = Crawler.detect_protection(headers, body)
        self.assertIn("siteground", result)

    def test_siteground_detects_sgcaptcha_body(self):
        headers = {}
        body = '<meta http-equiv="refresh" content="0;/.well-known/sgcaptcha/?r=%2Ftest">'
        result = Crawler.detect_protection(headers, body)
        self.assertIn("siteground", result)


# ------------------------------------------------------------------ #
# Auto-concurrency detection
# ------------------------------------------------------------------ #

class TestAutoConcurrency(unittest.TestCase):
    """Test auto_concurrency() CPU/RAM detection."""

    def test_returns_int(self):
        from web_crawler.config import auto_concurrency
        result = auto_concurrency()
        self.assertIsInstance(result, int)

    def test_minimum_is_2(self):
        from web_crawler.config import auto_concurrency
        result = auto_concurrency()
        self.assertGreaterEqual(result, 2)

    def test_maximum_is_32(self):
        from web_crawler.config import auto_concurrency
        result = auto_concurrency()
        self.assertLessEqual(result, 32)

    def test_respects_cpu_count(self):
        """With known CPU count, result should be at least 2."""
        from web_crawler.config import auto_concurrency
        import os
        cpus = os.cpu_count() or 2
        result = auto_concurrency()
        # Should be at least 2 and at most cpu*2 (before RAM cap)
        self.assertGreaterEqual(result, 2)
        self.assertLessEqual(result, max(cpus * 2, 2))

    @patch("os.cpu_count", return_value=None)
    def test_handles_unknown_cpu(self, _mock):
        from web_crawler.config import auto_concurrency
        result = auto_concurrency()
        self.assertGreaterEqual(result, 2)

    @patch("os.cpu_count", return_value=1)
    def test_single_cpu(self, _mock):
        from web_crawler.config import auto_concurrency
        result = auto_concurrency()
        self.assertGreaterEqual(result, 2)

    @patch("os.cpu_count", return_value=16)
    def test_many_cpus_capped(self, _mock):
        from web_crawler.config import auto_concurrency
        result = auto_concurrency()
        self.assertLessEqual(result, 32)


# ------------------------------------------------------------------ #
# Download extensions & concurrency
# ------------------------------------------------------------------ #

class TestDownloadExtensions(unittest.TestCase):
    """Test download-extension seeking and prioritization."""

    def _make_crawler(self, extensions=None, concurrency=1):
        with patch.object(Crawler, "_load_robots"):
            crawler = Crawler(
                start_url="https://example.com",
                output_dir=Path("/tmp/test_crawl_output"),
                respect_robots=False,
                download_extensions=extensions,
                concurrency=concurrency,
            )
        return crawler

    def test_default_no_extensions(self):
        crawler = self._make_crawler()
        self.assertEqual(crawler.download_extensions, frozenset())

    def test_extensions_stored(self):
        exts = frozenset({".zip", ".rar", ".bin"})
        crawler = self._make_crawler(extensions=exts)
        self.assertEqual(crawler.download_extensions, exts)

    def test_concurrency_stored(self):
        crawler = self._make_crawler(concurrency=10)
        self.assertEqual(crawler.concurrency, 10)

    def test_concurrency_auto_when_zero(self):
        """concurrency=0 triggers auto-detection (always >= 2)."""
        crawler = self._make_crawler(concurrency=0)
        self.assertGreaterEqual(crawler.concurrency, 2)

    def test_concurrency_auto_when_negative(self):
        """Negative concurrency also triggers auto-detection."""
        crawler = self._make_crawler(concurrency=-5)
        self.assertGreaterEqual(crawler.concurrency, 2)

    def test_extension_links_prioritized(self):
        """URLs matching download_extensions should be pushed to front."""
        exts = frozenset({".zip", ".bin"})
        crawler = self._make_crawler(extensions=exts)
        # Enqueue a regular URL first
        crawler._enqueue("https://example.com/page1.html", 0)
        # Enqueue a .zip URL (should be prioritized)
        crawler._enqueue("https://example.com/firmware.zip", 0)
        # The .zip should be at the front of the queue
        front_url, _ = crawler._queue[0]
        self.assertTrue(front_url.endswith(".zip"))

    def test_non_extension_link_not_prioritized(self):
        """URLs NOT matching download_extensions should go to back."""
        exts = frozenset({".zip", ".bin"})
        crawler = self._make_crawler(extensions=exts)
        crawler._enqueue("https://example.com/page1.html", 0)
        crawler._enqueue("https://example.com/page2.html", 0)
        front_url, _ = crawler._queue[0]
        self.assertEqual(front_url, "https://example.com/page1.html")


class TestExtractExtensionLinks(unittest.TestCase):
    """Test the extension-seeking link extraction regex."""

    def _make_crawler(self, exts):
        with patch.object(Crawler, "_load_robots"):
            return Crawler(
                start_url="https://example.com",
                output_dir=Path("/tmp/test_crawl_output"),
                respect_robots=False,
                download_extensions=exts,
            )

    def test_href_zip_found(self):
        html = b'<a href="/downloads/firmware.zip">Download</a>'
        exts = frozenset({".zip"})
        crawler = self._make_crawler(exts)
        links = crawler._extract_extension_links(
            html, "https://example.com/page.html", exts,
        )
        self.assertEqual(len(links), 1)
        self.assertIn("https://example.com/downloads/firmware.zip", links)

    def test_src_bin_found(self):
        html = b'<img src="/files/image.bin">'
        exts = frozenset({".bin"})
        crawler = self._make_crawler(exts)
        links = crawler._extract_extension_links(
            html, "https://example.com/page.html", exts,
        )
        self.assertEqual(len(links), 1)
        self.assertIn("https://example.com/files/image.bin", links)

    def test_relative_link_resolved(self):
        html = b'<a href="data/update.7z">Update</a>'
        exts = frozenset({".7z"})
        crawler = self._make_crawler(exts)
        links = crawler._extract_extension_links(
            html, "https://example.com/downloads/page.html", exts,
        )
        self.assertEqual(len(links), 1)
        self.assertIn("https://example.com/downloads/data/update.7z", links)

    def test_no_match_returns_empty(self):
        html = b'<a href="/page.html">Page</a>'
        exts = frozenset({".zip", ".rar"})
        crawler = self._make_crawler(exts)
        links = crawler._extract_extension_links(
            html, "https://example.com/page.html", exts,
        )
        self.assertEqual(len(links), 0)

    def test_multiple_extensions_found(self):
        html = (
            b'<a href="/fw.zip">ZIP</a>'
            b'<a href="/fw.rar">RAR</a>'
            b'<a href="/fw.exe">EXE</a>'
        )
        exts = frozenset({".zip", ".rar", ".exe"})
        crawler = self._make_crawler(exts)
        links = crawler._extract_extension_links(
            html, "https://example.com/page.html", exts,
        )
        self.assertEqual(len(links), 3)

    def test_query_string_preserved(self):
        html = b'<a href="/download/file.zip?v=2&token=abc">Get</a>'
        exts = frozenset({".zip"})
        crawler = self._make_crawler(exts)
        links = crawler._extract_extension_links(
            html, "https://example.com/page.html", exts,
        )
        self.assertEqual(len(links), 1)
        self.assertTrue(any("file.zip" in link for link in links))

    def test_protocol_relative_link(self):
        html = b'<a href="//cdn.example.com/file.tar.gz">Download</a>'
        exts = frozenset({".gz"})
        crawler = self._make_crawler(exts)
        links = crawler._extract_extension_links(
            html, "https://example.com/page.html", exts,
        )
        self.assertEqual(len(links), 1)
        self.assertTrue(any(l.startswith("https://") for l in links))

    def test_data_src_attribute(self):
        html = b'<div data-src="/lazy/firmware.bin"></div>'
        exts = frozenset({".bin"})
        crawler = self._make_crawler(exts)
        links = crawler._extract_extension_links(
            html, "https://example.com/page.html", exts,
        )
        self.assertEqual(len(links), 1)

    def test_no_extensions_returns_empty(self):
        """Crawler with no download_extensions returns empty set."""
        with patch.object(Crawler, "_load_robots"):
            crawler = Crawler(
                start_url="https://example.com",
                output_dir=Path("/tmp/test_crawl_output"),
                respect_robots=False,
            )
        html = b'<a href="/firmware.zip">Download</a>'
        links = crawler._extract_extension_links(
            html, "https://example.com/page.html", frozenset(),
        )
        self.assertEqual(len(links), 0)

    def test_parent_dir_relative_link(self):
        """../file.bin should resolve correctly."""
        html = b'<a href="../files/update.bin">Update</a>'
        exts = frozenset({".bin"})
        crawler = self._make_crawler(exts)
        links = crawler._extract_extension_links(
            html, "https://example.com/downloads/sub/page.html", exts,
        )
        self.assertEqual(len(links), 1)
        self.assertIn("https://example.com/downloads/files/update.bin", links)


# ------------------------------------------------------------------ #
# Upload-extension filtering
# ------------------------------------------------------------------ #

class TestUploadExtensions(unittest.TestCase):
    """Test upload_extensions parameter for git push filtering."""

    def _make_crawler(self, upload_exts=None):
        with patch.object(Crawler, "_load_robots"):
            return Crawler(
                start_url="https://example.com",
                output_dir=Path("/tmp/test_crawl_output"),
                respect_robots=False,
                upload_extensions=upload_exts,
            )

    def test_default_no_upload_extensions(self):
        crawler = self._make_crawler()
        self.assertEqual(crawler.upload_extensions, frozenset())

    def test_upload_extensions_stored(self):
        exts = frozenset({".zip", ".bin"})
        crawler = self._make_crawler(upload_exts=exts)
        self.assertEqual(crawler.upload_extensions, exts)

    def test_upload_extensions_none_gives_empty(self):
        crawler = self._make_crawler(upload_exts=None)
        self.assertEqual(crawler.upload_extensions, frozenset())

    def test_git_push_disabled_when_zero(self):
        """git_push_every=0 should not trigger push regardless of upload_extensions."""
        crawler = self._make_crawler(upload_exts=frozenset({".zip"}))
        crawler.git_push_every = 0
        # Should return immediately without error
        crawler._maybe_git_push()

    @patch("subprocess.run")
    def test_filtered_git_push_stages_only_matching(self, mock_run):
        """When upload_extensions is set, git add should target specific globs."""
        import subprocess as _sp
        with patch.object(Crawler, "_load_robots"):
            crawler = Crawler(
                start_url="https://example.com",
                output_dir=Path("/tmp/test_crawl_output"),
                respect_robots=False,
                upload_extensions=frozenset({".zip", ".bin"}),
                git_push_every=1,
            )
        crawler._stats["ok"] = 1
        crawler._maybe_git_push()
        # Should have called git add for README, each ext, commit, push
        calls = mock_run.call_args_list
        cmds = [c[0][0] for c in calls]
        # First call: git add README.md
        self.assertEqual(cmds[0], ["git", "add", "README.md"])
        # Should have ext-specific git add calls (2 extensions)
        ext_adds = [c for c in cmds if len(c) >= 4 and c[1] == "add"
                    and c[2] == "--"]
        self.assertEqual(len(ext_adds), 2)  # one per extension
        # Should have commit and push
        self.assertTrue(any(c[0:2] == ["git", "commit"] for c in cmds))
        self.assertTrue(any(c == ["git", "push"] for c in cmds))

    @patch("subprocess.run")
    def test_unfiltered_git_push_uses_add_all(self, mock_run):
        """Without upload_extensions, git add -A is used."""
        with patch.object(Crawler, "_load_robots"):
            crawler = Crawler(
                start_url="https://example.com",
                output_dir=Path("/tmp/test_crawl_output"),
                respect_robots=False,
                git_push_every=1,
            )
        crawler._stats["ok"] = 1
        crawler._maybe_git_push()
        calls = mock_run.call_args_list
        cmds = [c[0][0] for c in calls]
        self.assertTrue(any(c == ["git", "add", "-A"] for c in cmds))


if __name__ == "__main__":
    unittest.main()
