"""
Tests for the authentication module – login, session, cookie handling.
"""

import unittest
from unittest.mock import MagicMock, patch, PropertyMock

import requests

from huawei_crawler.auth.login import (
    b64encode_password,
    login,
    _deduplicate_cookies,
    detect_login_mode,
)
from huawei_crawler.auth.session import build_session, is_session_expired, base_url


class TestPasswordEncoding(unittest.TestCase):
    def test_b64encode_password_ascii(self):
        self.assertEqual(b64encode_password("admin"), "YWRtaW4=")

    def test_b64encode_password_hex_like(self):
        result = b64encode_password("eef90b1496430707")
        self.assertEqual(result, "ZWVmOTBiMTQ5NjQzMDcwNw==")

    def test_b64encode_password_empty(self):
        self.assertEqual(b64encode_password(""), "")


class TestBuildSession(unittest.TestCase):
    def test_session_has_keep_alive(self):
        session = build_session()
        self.assertEqual(session.headers["Connection"], "keep-alive")

    def test_session_has_user_agent(self):
        session = build_session()
        self.assertIn("Mozilla", session.headers["User-Agent"])


class TestBaseUrl(unittest.TestCase):
    def test_base_url(self):
        self.assertEqual(base_url("192.168.100.1"), "http://192.168.100.1")


class TestIsSessionExpired(unittest.TestCase):
    def _make_response(self, url="http://192.168.100.1/page.asp",
                       text="", status_code=200,
                       content_type="text/html",
                       cookies=None):
        resp = MagicMock(spec=requests.Response)
        resp.url = url
        resp.text = text
        resp.status_code = status_code
        resp.headers = {"Content-Type": content_type}
        resp.cookies = requests.cookies.RequestsCookieJar()
        if cookies:
            for name, value in cookies.items():
                resp.cookies.set(name, value)
        return resp

    def test_not_expired_normal_page(self):
        resp = self._make_response(text="<html>Admin panel</html>")
        self.assertFalse(is_session_expired(resp))

    def test_expired_cookie_default(self):
        resp = self._make_response(cookies={"Cookie": "default"})
        self.assertTrue(is_session_expired(resp))

    def test_expired_redirect_to_index_asp(self):
        resp = self._make_response(url="http://192.168.100.1/index.asp")
        self.assertTrue(is_session_expired(resp))

    def test_expired_redirect_to_login_asp(self):
        resp = self._make_response(url="http://192.168.100.1/login.asp")
        self.assertTrue(is_session_expired(resp))

    def test_not_expired_js_file_with_markers(self):
        """JS files that mention login markers should NOT trigger expiry."""
        text = "getElementById('txt_Username'); getElementById('txt_Password'); loginbutton"
        resp = self._make_response(
            text=text,
            content_type="application/javascript",
        )
        self.assertFalse(is_session_expired(resp))

    def test_expired_html_with_all_markers(self):
        text = '<input id="txt_Username"><input id="txt_Password"><button class="loginbutton">'
        resp = self._make_response(text=text)
        self.assertTrue(is_session_expired(resp))

    def test_not_expired_html_with_partial_markers(self):
        text = '<input id="txt_Username"><p>No password field</p>'
        resp = self._make_response(text=text)
        self.assertFalse(is_session_expired(resp))


class TestDeduplicateCookies(unittest.TestCase):
    def test_deduplicates_multiple_cookie_entries(self):
        session = requests.Session()
        session.cookies.set("Cookie", "old-value", domain="192.168.100.1", path="/")
        session.cookies.set("Cookie", "new-value", domain=".192.168.100.1", path="/")

        _deduplicate_cookies(session, "192.168.100.1")

        cookie_values = [c.value for c in session.cookies if c.name == "Cookie"]
        self.assertEqual(len(cookie_values), 1)
        self.assertEqual(cookie_values[0], "new-value")

    def test_no_dedup_needed_single_cookie(self):
        session = requests.Session()
        session.cookies.set("Cookie", "value", domain="192.168.100.1", path="/")

        _deduplicate_cookies(session, "192.168.100.1")

        cookie_values = [c.value for c in session.cookies if c.name == "Cookie"]
        self.assertEqual(len(cookie_values), 1)


class TestLoginCookieCleanup(unittest.TestCase):
    """Test that login() clears cookies before setting the pre-login cookie."""

    @patch("huawei_crawler.auth.login.detect_login_mode", return_value="MEGACABLE2")
    @patch("huawei_crawler.auth.login.get_rand_token", return_value="test_token_123")
    def test_login_clears_cookies_before_setting_prelogin(self, mock_token, mock_detect):
        """Verify cookies are cleared before the pre-login cookie is set."""
        session = build_session()
        # Simulate stale cookies from a previous session
        session.cookies.set("Cookie", "stale-session-id", domain="192.168.100.1", path="/")
        session.cookies.set("OtherCookie", "value", domain="192.168.100.1", path="/")

        # Mock the POST to login.cgi – return a successful response
        login_response = MagicMock(spec=requests.Response)
        login_response.status_code = 200
        login_response.text = "var pageName = '/'; top.location.replace(pageName);"
        login_response.headers = {}
        login_response.cookies = requests.cookies.RequestsCookieJar()
        login_response.url = "http://192.168.100.1/login.cgi"

        # Mock the follow-up GET to / – return a non-login page
        follow_response = MagicMock(spec=requests.Response)
        follow_response.status_code = 200
        follow_response.text = "<html><frameset>Admin Panel</frameset></html>"
        follow_response.url = "http://192.168.100.1/"
        follow_response.headers = {"Content-Type": "text/html"}
        follow_response.cookies = requests.cookies.RequestsCookieJar()

        def mock_post(url, **kwargs):
            # Simulate the server updating the Cookie via Set-Cookie
            session.cookies.set("Cookie", "body:Language:english:id=12345")
            return login_response

        with patch.object(session, "post", side_effect=mock_post):
            with patch.object(session, "get", return_value=follow_response):
                result = login(session, "192.168.100.1", "Mega_gpon", "test_password")

        self.assertIsNotNone(result)
        # Verify the old stale cookies are gone
        other_cookies = [c for c in session.cookies if c.name == "OtherCookie"]
        self.assertEqual(len(other_cookies), 0)
        # Verify the cookie value was updated from pre-login
        cookie_val = session.cookies.get("Cookie", "")
        self.assertNotEqual(cookie_val, "body:Language:english:id=-1")


if __name__ == "__main__":
    unittest.main()
