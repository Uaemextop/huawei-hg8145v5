"""Tests for the detection engine."""

import unittest

from web_crawler.detection import DetectionEngine, DetectionResult
from web_crawler.plugins.registry import PluginRegistry


class TestDetectionResult(unittest.TestCase):
    """Tests for DetectionResult dataclass."""

    def test_empty_result(self):
        r = DetectionResult(url="http://x")
        self.assertEqual(r.technologies, [])
        self.assertEqual(r.protections, [])
        self.assertFalse(r.has_captcha)
        self.assertFalse(r.has_waf)
        self.assertFalse(r.is_dynamic)
        self.assertEqual(r.suggested_strategy, "default")

    def test_summary_format(self):
        r = DetectionResult(
            url="http://x",
            technologies=["react"],
            protections=["cloudflare"],
            has_waf=True,
            is_dynamic=True,
            suggested_strategy="stealth",
        )
        s = r.summary
        self.assertIn("react", s)
        self.assertIn("cloudflare", s)
        self.assertIn("waf=yes", s)
        self.assertIn("dynamic=yes", s)
        self.assertIn("strategy=stealth", s)

    def test_empty_summary(self):
        r = DetectionResult(url="http://x")
        self.assertIn("strategy=default", r.summary)


class TestDetectionEngine(unittest.TestCase):
    """Tests for the DetectionEngine."""

    def setUp(self):
        self.reg = PluginRegistry()
        self.reg.auto_discover()
        self.engine = DetectionEngine(self.reg)

    def test_analyse_basic(self):
        result = self.engine.analyse(
            "http://example.com",
            {"Server": "nginx"},
            "<html>hello</html>",
        )
        self.assertIsInstance(result, DetectionResult)
        self.assertIn("nginx", result.technologies)
        self.assertEqual(result.suggested_strategy, "default")

    def test_analyse_detects_waf(self):
        result = self.engine.analyse(
            "http://example.com",
            {"cf-ray": "abc", "Server": "cloudflare"},
            "",
        )
        self.assertTrue(result.has_waf)
        self.assertIn("cloudflare", result.protections)

    def test_analyse_detects_captcha(self):
        result = self.engine.analyse(
            "http://example.com",
            {},
            '<div class="g-recaptcha">recaptcha</div>',
        )
        self.assertTrue(result.has_captcha)
        self.assertEqual(result.suggested_strategy, "browser")

    def test_analyse_detects_dynamic(self):
        result = self.engine.analyse(
            "http://example.com",
            {},
            '<div id="root"></div><script src="_next/static/chunks/main.js">',
        )
        self.assertIn("nextjs", result.technologies)
        self.assertTrue(result.is_dynamic)

    def test_analyse_stealth_for_waf_no_captcha(self):
        result = self.engine.analyse(
            "http://example.com",
            {"cf-ray": "abc", "Server": "cloudflare"},
            "<html>normal page</html>",
        )
        self.assertTrue(result.has_waf)
        self.assertFalse(result.has_captcha)
        self.assertEqual(result.suggested_strategy, "stealth")


if __name__ == "__main__":
    unittest.main()
