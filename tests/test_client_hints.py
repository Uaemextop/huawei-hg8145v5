"""Tests for Client Hints header generation and session setup."""

import unittest

from crawl4ai.extensions.bypass.session import (
    _client_hints_for_ua,
    build_session,
    random_headers,
)
from crawl4ai.extensions.settings import USER_AGENTS


class TestClientHintsForUA(unittest.TestCase):
    """Verify _client_hints_for_ua derives correct headers."""

    def test_chrome_windows(self):
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        )
        hints = _client_hints_for_ua(ua)
        self.assertIn("sec-ch-ua", hints)
        self.assertIn("131", hints["sec-ch-ua"])
        self.assertIn("Google Chrome", hints["sec-ch-ua"])
        self.assertEqual(hints["sec-ch-ua-mobile"], "?0")
        self.assertEqual(hints["sec-ch-ua-platform"], '"Windows"')

    def test_edge_windows(self):
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
        )
        hints = _client_hints_for_ua(ua)
        self.assertIn("Microsoft Edge", hints["sec-ch-ua"])

    def test_opera_windows(self):
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36 OPR/114.0.0.0"
        )
        hints = _client_hints_for_ua(ua)
        self.assertIn("Opera", hints["sec-ch-ua"])

    def test_firefox_no_brand(self):
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) "
            "Gecko/20100101 Firefox/133.0"
        )
        hints = _client_hints_for_ua(ua)
        self.assertNotIn("sec-ch-ua", hints)
        self.assertEqual(hints["sec-ch-ua-mobile"], "?0")
        self.assertEqual(hints["sec-ch-ua-platform"], '"Windows"')

    def test_safari_macos_no_brand(self):
        ua = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/17.6 Safari/605.1.15"
        )
        hints = _client_hints_for_ua(ua)
        self.assertNotIn("sec-ch-ua", hints)
        self.assertEqual(hints["sec-ch-ua-platform"], '"macOS"')

    def test_chrome_android_mobile(self):
        ua = (
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Mobile Safari/537.36"
        )
        hints = _client_hints_for_ua(ua)
        self.assertEqual(hints["sec-ch-ua-mobile"], "?1")
        self.assertEqual(hints["sec-ch-ua-platform"], '"Android"')

    def test_iphone_ios(self):
        ua = (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/17.6 Mobile/15E148 Safari/604.1"
        )
        hints = _client_hints_for_ua(ua)
        self.assertEqual(hints["sec-ch-ua-mobile"], "?1")
        self.assertEqual(hints["sec-ch-ua-platform"], '"iOS"')

    def test_chrome_linux(self):
        ua = (
            "Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        )
        hints = _client_hints_for_ua(ua)
        self.assertEqual(hints["sec-ch-ua-platform"], '"Linux"')

    def test_all_user_agents_have_mobile_and_platform(self):
        """Every UA in the rotation pool must produce mobile + platform."""
        for ua in USER_AGENTS:
            hints = _client_hints_for_ua(ua)
            self.assertIn("sec-ch-ua-mobile", hints, msg=ua)
            self.assertIn("sec-ch-ua-platform", hints, msg=ua)


class TestBuildSession(unittest.TestCase):
    """Verify build_session includes Client Hints."""

    def test_session_has_client_hints(self):
        session = build_session()
        self.assertIn("sec-ch-ua-mobile", session.headers)
        self.assertIn("sec-ch-ua-platform", session.headers)

    def test_session_has_standard_headers(self):
        session = build_session()
        self.assertIn("User-Agent", session.headers)
        self.assertIn("Accept", session.headers)
        self.assertIn("Sec-Fetch-Dest", session.headers)


class TestRandomHeaders(unittest.TestCase):
    """Verify random_headers includes Client Hints."""

    def test_random_headers_have_client_hints(self):
        headers = random_headers()
        self.assertIn("sec-ch-ua-mobile", headers)
        self.assertIn("sec-ch-ua-platform", headers)

    def test_random_headers_with_referer(self):
        headers = random_headers("https://example.com")
        self.assertEqual(headers["Referer"], "https://example.com")
        self.assertIn("sec-ch-ua-mobile", headers)


if __name__ == "__main__":
    unittest.main()
