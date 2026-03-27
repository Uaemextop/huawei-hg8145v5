"""Tests for WAF / protection detection – false-positive prevention."""

import unittest

from crawl4ai.extensions.crawler.engine import Crawler


class TestDetectProtectionAkamaiFalsePositive(unittest.TestCase):
    """Akamai CDN headers must NOT trigger WAF detection.

    Sites served through Akamai CDN include ``akamai-grn``,
    ``x-akamai-transformed``, and ``server: AkamaiGHost`` on every
    response.  These indicate the CDN, not a WAF block.
    """

    def test_akamai_grn_header_no_false_positive(self):
        """akamai-grn tracking header must not flag the page."""
        headers = {
            "content-type": "text/html",
            "server": "nginx",
            "akamai-grn": "0.b5643017.1773686618.23c118ad",
        }
        body = "<html><head><title>HP Support</title></head><body>OK</body></html>"
        result = Crawler.detect_protection(headers, body)
        self.assertEqual(result, [])

    def test_akamaighost_server_no_false_positive(self):
        """server: AkamaiGHost must not flag the page."""
        headers = {
            "content-type": "text/html",
            "server": "AkamaiGHost",
        }
        body = "<html><head><title>Welcome</title></head><body>Hello</body></html>"
        result = Crawler.detect_protection(headers, body)
        self.assertEqual(result, [])

    def test_akamai_transformed_header_no_false_positive(self):
        """x-akamai-transformed header must not flag the page."""
        headers = {
            "content-type": "text/html",
            "server": "nginx",
            "x-akamai-transformed": "9 - 0 pmb=mRUM,2",
            "akamai-grn": "0.abc.123.def",
        }
        body = "<html><body>Normal content</body></html>"
        result = Crawler.detect_protection(headers, body)
        self.assertEqual(result, [])

    def test_real_akamai_block_page_detected(self):
        """Actual Akamai WAF block page (errors.edgesuite.net) must be detected."""
        headers = {
            "content-type": "text/html",
            "server": "AkamaiGHost",
            "akamai-grn": "0.b5643017.1773686586.23be5d2b",
        }
        body = (
            "<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD><BODY>"
            "<H1>Access Denied</H1> You don't have permission to access "
            '"http://support.hp.com/" on this server.<P>'
            "Reference #18.b5643017.1773686586.23be5d2b"
            "<P>https://errors.edgesuite.net/18.b5643017.1773686586.23be5d2b</P>"
            "</BODY></HTML>"
        )
        result = Crawler.detect_protection(headers, body)
        self.assertIn("akamai", result)

    def test_akamai_bot_manager_cookie_detected(self):
        """ak_bmsc cookie in Set-Cookie header should trigger detection."""
        headers = {
            "content-type": "text/html",
            "set-cookie": "ak_bmsc=abc123; path=/; secure",
        }
        body = "<html><body>Challenge</body></html>"
        result = Crawler.detect_protection(headers, body)
        self.assertIn("akamai", result)


class TestDetectProtectionOtherWAFs(unittest.TestCase):
    """Ensure other WAF detections still work after the fix."""

    def test_cloudflare_challenge_detected(self):
        headers = {"cf-mitigated": "challenge"}
        body = "<html><body>Just a moment...</body></html>"
        result = Crawler.detect_protection(headers, body)
        self.assertIn("cloudflare", result)

    def test_siteground_captcha_detected(self):
        headers = {"content-type": "text/html"}
        body = '<html><body><form id="sg-captcha-form">solve</form></body></html>'
        result = Crawler.detect_protection(headers, body)
        self.assertIn("siteground", result)

    def test_clean_page_no_detection(self):
        headers = {"content-type": "text/html", "server": "nginx"}
        body = "<html><head><title>Hello World</title></head><body>Clean page</body></html>"
        result = Crawler.detect_protection(headers, body)
        self.assertEqual(result, [])

    def test_permissions_policy_excluded(self):
        """Permissions-Policy with cloudflare.com must not trigger detection."""
        headers = {
            "content-type": "text/html",
            "permissions-policy": "interest-cohort=(), accelerometer=(self 'https://cloudflare.com')",
        }
        body = "<html><body>Normal page</body></html>"
        result = Crawler.detect_protection(headers, body)
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
