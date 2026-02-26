"""
Tests for the huawei_crawler package.

Covers:
  - Package import and structure
  - Session cookie restoration after refresh_token() call
  - URL normalisation edge cases
  - Link extraction from HTML / JS / CSS
  - is_session_expired() detection logic
"""

import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path

import requests


class TestPackageStructure(unittest.TestCase):
    """Verify that the package and all submodules are importable."""

    def test_package_import(self):
        import huawei_crawler
        self.assertTrue(hasattr(huawei_crawler, "Crawler"))

    def test_submodules_importable(self):
        from huawei_crawler import config, auth, session, utils, crawler, cli
        from huawei_crawler.extract import extract_links
        from huawei_crawler.extract import css, js, html, core

    def test_extract_subpackage(self):
        from huawei_crawler.extract import extract_links
        self.assertTrue(callable(extract_links))


class TestRefreshTokenSessionSafety(unittest.TestCase):
    """
    Verify that refresh_token() restores the session cookie when the token
    endpoint resets it to 'default' (the logged-out state).

    This is the root-cause fix for the session-loop bug described in the
    problem statement: the POST to GetRandToken.asp was silently invalidating
    the authenticated session because the endpoint may not exist on all
    firmware versions and the router responds with Set-Cookie: Cookie=default.
    """

    def _make_session(self, cookie_value: str) -> requests.Session:
        s = requests.Session()
        s.cookies.set("Cookie", cookie_value, domain="192.168.100.1", path="/")
        return s

    def test_cookie_restored_when_reset_to_default(self):
        """Token endpoint resets cookie → refresh_token restores it."""
        from huawei_crawler.auth import refresh_token

        session = self._make_session("body:Language:english:id=1")

        def _reset_cookie(*args, **kwargs):
            session.cookies.set("Cookie", "default", domain="192.168.100.1", path="/")
            resp = MagicMock()
            resp.text = "tooshort"  # won't be saved as token
            return resp

        with patch.object(session, "post", side_effect=_reset_cookie):
            refresh_token(session, "192.168.100.1")

        self.assertEqual(session.cookies.get("Cookie"), "body:Language:english:id=1")

    def test_valid_token_returned_and_cookie_preserved(self):
        """Token endpoint returns a valid token without resetting cookie."""
        from huawei_crawler.auth import refresh_token

        session = self._make_session("body:Language:english:id=1")
        VALID_TOKEN = "abcd1234efgh"

        def _good_response(*args, **kwargs):
            resp = MagicMock()
            resp.text = VALID_TOKEN
            return resp

        with patch.object(session, "post", side_effect=_good_response):
            token = refresh_token(session, "192.168.100.1")

        self.assertEqual(token, VALID_TOKEN)
        self.assertEqual(session.cookies.get("Cookie"), "body:Language:english:id=1")

    def test_request_exception_leaves_cookie_intact(self):
        """Token refresh network failure must not modify the session cookie."""
        from huawei_crawler.auth import refresh_token

        session = self._make_session("body:Language:english:id=1")

        with patch.object(session, "post", side_effect=requests.RequestException("timeout")):
            result = refresh_token(session, "192.168.100.1", current_token="prev_token")

        self.assertEqual(result, "prev_token")
        self.assertEqual(session.cookies.get("Cookie"), "body:Language:english:id=1")

    def test_default_cookie_stays_default(self):
        """If the cookie was already 'default' before the call, no change."""
        from huawei_crawler.auth import refresh_token

        session = self._make_session("default")

        def _reset_cookie(*args, **kwargs):
            resp = MagicMock()
            resp.text = "tooshort"
            return resp

        with patch.object(session, "post", side_effect=_reset_cookie):
            refresh_token(session, "192.168.100.1")

        # Still default – we do NOT restore a cookie that was already default
        self.assertEqual(session.cookies.get("Cookie"), "default")


class TestPreLoginCookieDomain(unittest.TestCase):
    """
    Verify the pre-login cookie / session cookie interaction.

    Empirically verified (Python http.cookiejar behaviour):

      * Manually setting cookie WITHOUT domain= stores it under domain="" in
        the jar.  When the router responds with Set-Cookie (domain from request
        URL = "192.168.100.1"), that creates a SECOND entry → duplicate cookies
        → both sent to router → pre-login value (id=-1) can take precedence.

      * Manually setting cookie WITH domain="192.168.100.1" stores it under
        the same key that the router's Set-Cookie response will write to →
        server's authenticated cookie OVERWRITES ours → single clean entry. ✓

    Therefore login() uses domain=host when setting the pre-login cookie.
    """

    def _make_server_cookie(self, value):
        """Build a cookie resembling what the router's Set-Cookie header produces."""
        import http.cookiejar
        return http.cookiejar.Cookie(
            version=0, name="Cookie", value=value,
            port=None, port_specified=False,
            domain="192.168.100.1", domain_specified=False, domain_initial_dot=False,
            path="/", path_specified=True,
            secure=False, expires=None, discard=True,
            comment=None, comment_url=None, rest={}, rfc2109=False,
        )

    def test_domain_host_allows_server_to_overwrite_prelogin_cookie(self):
        """
        With domain=host the server's Set-Cookie (domain_specified=False) overwrites
        the pre-login cookie stored under the same domain key → single entry. ✓
        """
        session = requests.Session()
        session.cookies.set("Cookie", "body:Language:english:id=-1",
                            domain="192.168.100.1", path="/")

        # Simulate Set-Cookie from the router (domain_specified=False)
        session.cookies.set_cookie(self._make_server_cookie("body:Language:english:id=7"))

        all_cookies = [c for c in session.cookies if c.name == "Cookie"]
        self.assertEqual(len(all_cookies), 1,
                         "Expected exactly one Cookie entry with domain=host")
        self.assertEqual(session.cookies.get("Cookie"), "body:Language:english:id=7")

    def test_no_domain_arg_creates_duplicate_entries(self):
        """
        Without domain=, the manually-set cookie (domain='') and the server-set
        cookie (domain='192.168.100.1') are stored in different jar buckets
        → duplicate entries → the pre-login value may be sent to the router. ✗
        """
        session = requests.Session()
        # No domain= : stored under domain=""
        session.cookies.set("Cookie", "body:Language:english:id=-1", path="/")

        session.cookies.set_cookie(self._make_server_cookie("body:Language:english:id=7"))

        all_cookies = [c for c in session.cookies if c.name == "Cookie"]
        # Two entries exist: domain="" and domain="192.168.100.1"
        self.assertGreater(len(all_cookies), 1,
                           "Without domain= there should be duplicate Cookie entries")

    def test_refresh_token_rejects_html_response(self):
        """
        An HTML error page returned by a missing token endpoint must NOT be
        stored as X_HW_Token.
        """
        from huawei_crawler.auth import refresh_token

        session = requests.Session()
        session.cookies.set("Cookie", "body:Language:english:id=1",
                            domain="192.168.100.1", path="/")

        def _html_403(*args, **kwargs):
            resp = MagicMock()
            resp.text = "<!DOCTYPE html><html><body>403 Forbidden</body></html>"
            return resp

        with patch.object(session, "post", side_effect=_html_403):
            token = refresh_token(session, "192.168.100.1", current_token="prev")

        # HTML body must NOT be stored as the token
        self.assertEqual(token, "prev",
                         "HTML error page must not replace a valid previous token")


class TestCrawlerRefreshTokenFix(unittest.TestCase):
    """Same session-cookie protection test for the root crawler.py module."""

    def test_root_crawler_cookie_restored(self):
        import crawler as root_crawler  # root crawler.py
        c = root_crawler.Crawler(
            "192.168.100.1", "user", "pass", Path("/tmp/_test_crawl")
        )
        c.session.cookies.set(
            "Cookie", "body:Language:english:id=5",
            domain="192.168.100.1", path="/"
        )

        def _reset_cookie(*args, **kwargs):
            c.session.cookies.set("Cookie", "default", domain="192.168.100.1", path="/")
            resp = MagicMock()
            resp.text = "tooshort"
            return resp

        with patch.object(c.session, "post", side_effect=_reset_cookie):
            c._refresh_token()

        self.assertEqual(c.session.cookies.get("Cookie"), "body:Language:english:id=5")


class TestIsSessionExpired(unittest.TestCase):
    """Validate the session-expiry heuristics."""

    def _make_resp(self, url, text="", ct="text/html", cookie=None):
        resp = MagicMock(spec=requests.Response)
        resp.url = url
        resp.text = text
        resp.headers = {"Content-Type": ct}
        resp.cookies = requests.cookies.RequestsCookieJar()
        if cookie:
            resp.cookies.set("Cookie", cookie)
        return resp

    def test_login_page_redirect_detected(self):
        from huawei_crawler.auth import is_session_expired
        resp = self._make_resp("http://192.168.100.1/index.asp")
        self.assertTrue(is_session_expired(resp))

    def test_login_asp_redirect_detected(self):
        from huawei_crawler.auth import is_session_expired
        resp = self._make_resp("http://192.168.100.1/login.asp")
        self.assertTrue(is_session_expired(resp))

    def test_cookie_default_detected(self):
        from huawei_crawler.auth import is_session_expired
        resp = self._make_resp("http://192.168.100.1/", cookie="default")
        self.assertTrue(is_session_expired(resp))

    def test_admin_page_not_expired(self):
        from huawei_crawler.auth import is_session_expired
        resp = self._make_resp("http://192.168.100.1/html/ssmp/wlan.asp", text="<html>wifi</html>")
        self.assertFalse(is_session_expired(resp))

    def test_js_with_markers_not_expired(self):
        """JS file containing login marker strings should NOT be flagged."""
        from huawei_crawler.auth import is_session_expired
        js_text = "document.getElementById('txt_Username'); document.getElementById('txt_Password'); loginbutton"
        resp = self._make_resp(
            "http://192.168.100.1/js/util.js",
            text=js_text,
            ct="application/javascript",
        )
        self.assertFalse(is_session_expired(resp))

    def test_all_markers_in_html_detected(self):
        """HTML with ALL login markers present is flagged as expired."""
        from huawei_crawler.auth import is_session_expired
        html = "txt_Username txt_Password loginbutton"
        resp = self._make_resp("http://192.168.100.1/", text=html, ct="text/html")
        self.assertTrue(is_session_expired(resp))


class TestNormaliseUrl(unittest.TestCase):
    """URL normalisation edge-cases."""

    def test_absolute_same_host(self):
        from huawei_crawler.utils import normalise_url
        r = normalise_url("http://192.168.100.1/test.asp",
                          "http://192.168.100.1/", "http://192.168.100.1")
        self.assertEqual(r, "http://192.168.100.1/test.asp")

    def test_external_url_rejected(self):
        from huawei_crawler.utils import normalise_url
        r = normalise_url("http://example.com/page",
                          "http://192.168.100.1/", "http://192.168.100.1")
        self.assertIsNone(r)

    def test_data_url_rejected(self):
        from huawei_crawler.utils import normalise_url
        r = normalise_url("data:image/png;base64,abc",
                          "http://192.168.100.1/", "http://192.168.100.1")
        self.assertIsNone(r)

    def test_path_ending_comma_rejected(self):
        """JS regex literals like replace(/'/g, ...) create false paths."""
        from huawei_crawler.utils import normalise_url
        r = normalise_url("/g,",
                          "http://192.168.100.1/test.js", "http://192.168.100.1")
        self.assertIsNone(r)

    def test_cache_buster_stripped(self):
        from huawei_crawler.utils import normalise_url
        r = normalise_url("http://192.168.100.1/test.asp?202406291158020553",
                          "http://192.168.100.1/", "http://192.168.100.1")
        self.assertEqual(r, "http://192.168.100.1/test.asp")


class TestExtractLinks(unittest.TestCase):
    """Verify that extract_links returns expected URLs."""

    BASE = "http://192.168.100.1"

    def test_html_href(self):
        from huawei_crawler.extract import extract_links
        html = b'<a href="/about.asp">About</a>'
        links = extract_links(html, "text/html", self.BASE + "/", self.BASE)
        self.assertIn(self.BASE + "/about.asp", links)

    def test_html_script_src(self):
        from huawei_crawler.extract import extract_links
        html = b'<script src="/js/util.js"></script>'
        links = extract_links(html, "text/html", self.BASE + "/", self.BASE)
        self.assertIn(self.BASE + "/js/util.js", links)

    def test_css_url(self):
        from huawei_crawler.extract import extract_links
        css = b"body { background: url('/images/bg.png'); }"
        links = extract_links(css, "text/css", self.BASE + "/style.css", self.BASE)
        self.assertIn(self.BASE + "/images/bg.png", links)

    def test_js_window_location(self):
        from huawei_crawler.extract import extract_links
        js = b"window.location.href = '/html/ssmp/wlan.asp';"
        links = extract_links(js, "application/javascript", self.BASE + "/app.js", self.BASE)
        self.assertIn(self.BASE + "/html/ssmp/wlan.asp", links)

    def test_asp_treated_as_html(self):
        """ASP files should be parsed as HTML regardless of Content-Type."""
        from huawei_crawler.extract import extract_links
        asp = b'<a href="/cfg.asp">Config</a>'
        links = extract_links(asp, "text/plain", self.BASE + "/page.asp", self.BASE)
        self.assertIn(self.BASE + "/cfg.asp", links)


if __name__ == "__main__":
    unittest.main(verbosity=2)
