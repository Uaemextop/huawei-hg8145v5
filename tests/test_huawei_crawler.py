"""Comprehensive tests for the huawei_crawler package."""

import base64
import hashlib
import json
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import MagicMock, patch

from huawei_crawler.config import (
    CRAWLABLE_TYPES,
    DEFAULT_HOST,
    _AUTH_PAGE_PATHS,
    _BLOCKED_PATH_RE,
    _LOGIN_MARKERS,
)
from huawei_crawler.auth.password import b64encode_password, pbkdf2_sha256_password
from huawei_crawler.auth.login import is_session_expired
from huawei_crawler.extraction.links import extract_links
from huawei_crawler.extraction.css import _extract_css_urls
from huawei_crawler.extraction.javascript import _extract_js_paths
from huawei_crawler.extraction.json_extract import _extract_json_paths
from huawei_crawler.utils.url import normalise_url, url_key, url_to_local_path, smart_local_path
from huawei_crawler.utils.files import save_file, content_hash
from huawei_crawler.crawler import Crawler
from huawei_crawler.session import build_session, base_url

BASE = f"http://{DEFAULT_HOST}"


# ---------------------------------------------------------------
# 1. Session Loop Fix Tests
# ---------------------------------------------------------------
class TestSessionLoopFix(unittest.TestCase):
    """Verify the session-loop fix: auth pages are excluded from BFS."""

    def test_auth_page_paths_includes_root(self):
        self.assertIn("/", _AUTH_PAGE_PATHS)

    def test_auth_page_paths_includes_index_asp(self):
        self.assertIn("/index.asp", _AUTH_PAGE_PATHS)

    def test_auth_page_paths_includes_login_asp(self):
        self.assertIn("/login.asp", _AUTH_PAGE_PATHS)

    @patch("huawei_crawler.crawler.login", return_value=f"{BASE}/html/ssmp/default/main.asp")
    @patch("huawei_crawler.crawler.build_session")
    def test_crawler_run_does_not_seed_root_url(self, mock_build, mock_login):
        """After run(), '/' must not appear in the BFS queue."""
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.content = b"<html><head></head><body>test</body></html>"
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_session.get.return_value = mock_resp
        mock_session.post.return_value = MagicMock(text="abc123token", ok=True)
        mock_session.cookies = MagicMock()
        mock_session.headers = {}
        mock_build.return_value = mock_session

        with tempfile.TemporaryDirectory() as tmpdir:
            c = Crawler("192.168.100.1", "user", "pass", Path(tmpdir))
            c.session = mock_session
            # Simulate run seeding: call _save_pre_auth then check queue
            c._save_pre_auth("/index.asp")
            c._save_pre_auth("/")

            # The root URL and /index.asp should be marked visited
            root_key = url_key(BASE + "/")
            index_key = url_key(BASE + "/index.asp")
            self.assertIn(root_key, c._visited)
            self.assertIn(index_key, c._visited)

            # Neither "/" nor "/index.asp" should be in the queue
            queue_paths = [urllib.parse.urlparse(u).path for u in c._queue]
            self.assertNotIn("/", queue_paths)
            self.assertNotIn("/index.asp", queue_paths)

    def test_fetch_and_process_skips_auth_pages(self):
        """_fetch_and_process must NOT make HTTP requests for auth page URLs."""
        from collections import deque

        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = Path(tmpdir)
            with patch("huawei_crawler.crawler.build_session") as mock_build:
                mock_session = MagicMock()
                mock_build.return_value = mock_session
                c = Crawler(DEFAULT_HOST, "user", "pass", outdir)
                c.session = mock_session

                # Create a local file so the auth-page branch parses it
                index_file = outdir / "index.html"
                index_file.write_text("<html><head></head><body>test</body></html>")

                c._fetch_and_process(f"{BASE}/")
                c.session.get.assert_not_called()

                # Also check /index.asp
                index_asp = outdir / "index.asp"
                index_asp.write_text("<html>test</html>")
                c._fetch_and_process(f"{BASE}/index.asp")
                c.session.get.assert_not_called()

    def test_is_session_expired_root_url_not_false_positive(self):
        """A response from '/' that contains login markers IS expired.

        The fix is that _AUTH_PAGE_PATHS prevents '/' from ever being
        fetched post-auth, so this code path is never reached in practice.
        """
        resp = MagicMock()
        resp.cookies = MagicMock()
        resp.cookies.get.return_value = ""
        resp.url = f"{BASE}/"
        resp.headers = {"Content-Type": "text/html"}
        resp.text = (
            '<input id="txt_Username">'
            '<input id="txt_Password">'
            '<button class="loginbutton">'
        )
        # "/" is not in the explicit path check (/index.asp, /login.asp),
        # but the body markers trigger expiry detection.
        result = is_session_expired(resp)
        self.assertTrue(result)


# ---------------------------------------------------------------
# 2. Password Encoding Tests
# ---------------------------------------------------------------
class TestPasswordEncoding(unittest.TestCase):

    def test_b64encode_password(self):
        result = b64encode_password("admin123")
        expected = base64.b64encode(b"admin123").decode("ascii")
        self.assertEqual(result, expected)

    def test_b64encode_password_empty(self):
        self.assertEqual(b64encode_password(""), base64.b64encode(b"").decode("ascii"))

    def test_pbkdf2_sha256_password(self):
        password = "testpass"
        salt = "randomsalt"
        iterations = 1000

        # Reproduce the expected output manually
        dk = hashlib.pbkdf2_hmac("sha256", b"testpass", b"randomsalt", 1000, dklen=32)
        pbkdf2_hex = dk.hex()
        sha256_hex = hashlib.sha256(pbkdf2_hex.encode("utf-8")).hexdigest()
        expected = base64.b64encode(sha256_hex.encode("utf-8")).decode("ascii")

        result = pbkdf2_sha256_password(password, salt, iterations)
        self.assertEqual(result, expected)


# ---------------------------------------------------------------
# 3. URL Normalization Tests
# ---------------------------------------------------------------
class TestURLNormalization(unittest.TestCase):

    def test_normalise_url_absolute(self):
        result = normalise_url(
            f"{BASE}/html/page.asp", f"{BASE}/index.asp", BASE
        )
        self.assertEqual(result, f"{BASE}/html/page.asp")

    def test_normalise_url_relative(self):
        result = normalise_url(
            "page.asp", f"{BASE}/html/index.asp", BASE
        )
        self.assertEqual(result, f"{BASE}/html/page.asp")

    def test_normalise_url_rejects_external(self):
        result = normalise_url(
            "http://evil.com/steal", f"{BASE}/index.asp", BASE
        )
        self.assertIsNone(result)

    def test_normalise_url_rejects_javascript(self):
        result = normalise_url(
            "javascript:void(0)", f"{BASE}/index.asp", BASE
        )
        self.assertIsNone(result)

    def test_normalise_url_strips_cache_buster(self):
        result = normalise_url(
            "/Cuscss/login.css?202406291158020553184798",
            f"{BASE}/index.asp",
            BASE,
        )
        self.assertEqual(result, f"{BASE}/Cuscss/login.css")

    def test_normalise_url_rejects_trailing_comma(self):
        result = normalise_url(
            "/g,", f"{BASE}/index.asp", BASE
        )
        self.assertIsNone(result)

    def test_normalise_url_rejects_data_uri(self):
        result = normalise_url("data:image/png;base64,abc", f"{BASE}/", BASE)
        self.assertIsNone(result)

    def test_url_key_strips_query(self):
        key1 = url_key(f"{BASE}/page.asp?x=1")
        key2 = url_key(f"{BASE}/page.asp?y=2")
        self.assertEqual(key1, key2)
        self.assertNotIn("?", key1)


# ---------------------------------------------------------------
# 4. Link Extraction Tests
# ---------------------------------------------------------------
class TestLinkExtraction(unittest.TestCase):

    def test_extract_links_html(self):
        html = (
            '<html><head>'
            '<link rel="stylesheet" href="/Cuscss/style.css">'
            '<script src="/js/app.js"></script>'
            '</head><body>'
            '<a href="/html/page.asp">link</a>'
            '<img src="/images/logo.png">'
            '</body></html>'
        )
        links = extract_links(html, "text/html", f"{BASE}/index.asp", BASE)
        self.assertIn(f"{BASE}/Cuscss/style.css", links)
        self.assertIn(f"{BASE}/js/app.js", links)
        self.assertIn(f"{BASE}/html/page.asp", links)
        self.assertIn(f"{BASE}/images/logo.png", links)

    def test_extract_links_css(self):
        css = (
            "body { background: url('/images/bg.png'); }\n"
            "@import '/Cuscss/base.css';\n"
        )
        links = extract_links(css, "text/css", f"{BASE}/Cuscss/style.css", BASE)
        self.assertIn(f"{BASE}/images/bg.png", links)
        self.assertIn(f"{BASE}/Cuscss/base.css", links)

    def test_extract_links_javascript(self):
        js = """
        var page = '/html/ssmp/wlan/wlan.asp';
        fetch('/api/data.json');
        window.location.href = '/html/main.asp';
        """
        links = extract_links(js, "application/javascript", f"{BASE}/js/app.js", BASE)
        self.assertIn(f"{BASE}/html/ssmp/wlan/wlan.asp", links)
        self.assertIn(f"{BASE}/api/data.json", links)
        self.assertIn(f"{BASE}/html/main.asp", links)

    def test_extract_links_json(self):
        data = json.dumps({
            "page": "/html/status.asp",
            "nested": {"path": "/api/info.cgi?ObjPath=device"},
            "list": ["/html/wan.asp"],
        })
        links = extract_links(data, "application/json", f"{BASE}/api/menu.json", BASE)
        self.assertIn(f"{BASE}/html/status.asp", links)
        self.assertIn(f"{BASE}/html/wan.asp", links)


# ---------------------------------------------------------------
# 5. File Utilities Tests
# ---------------------------------------------------------------
class TestFileUtilities(unittest.TestCase):

    def test_save_file_creates_directories(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "a" / "b" / "file.txt"
            save_file(target, b"hello world")
            self.assertTrue(target.exists())
            self.assertEqual(target.read_bytes(), b"hello world")

    def test_content_hash(self):
        data = b"some binary content"
        h = content_hash(data)
        expected = hashlib.sha256(data).hexdigest()[:16]
        self.assertEqual(h, expected)
        self.assertEqual(len(h), 16)

    def test_content_hash_different_data(self):
        self.assertNotEqual(content_hash(b"aaa"), content_hash(b"bbb"))

    def test_url_to_local_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir)
            # Normal file
            p = url_to_local_path(f"{BASE}/Cuscss/login.css", out)
            self.assertEqual(p, out / "Cuscss" / "login.css")

            # Root → index.html
            p = url_to_local_path(f"{BASE}/", out)
            self.assertEqual(p, out / "index.html")

            # Directory with trailing slash
            p = url_to_local_path(f"{BASE}/html/ssmp/", out)
            self.assertEqual(p, out / "html" / "ssmp" / "index.html")

    def test_smart_local_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir)

            # Normal file with extension
            p = smart_local_path(f"{BASE}/js/app.js", out, "application/javascript")
            self.assertEqual(p, out / "js" / "app.js")

            # Extensionless URL with text/html CT
            p = smart_local_path(f"{BASE}/status", out, "text/html")
            self.assertEqual(p, out / "status.html")

            # Content-Disposition filename override
            p = smart_local_path(
                f"{BASE}/download/data",
                out,
                "application/octet-stream",
                'attachment; filename="backup.bin"',
            )
            self.assertEqual(p, out / "download" / "backup.bin")


# ---------------------------------------------------------------
# 6. Config Tests
# ---------------------------------------------------------------
class TestConfig(unittest.TestCase):

    def test_blocked_path_re_matches_logout(self):
        self.assertIsNotNone(_BLOCKED_PATH_RE.search("/logout"))

    def test_blocked_path_re_matches_reboot(self):
        self.assertIsNotNone(_BLOCKED_PATH_RE.search("/reboot"))

    def test_blocked_path_re_matches_factory(self):
        self.assertIsNotNone(_BLOCKED_PATH_RE.search("/factory"))

    def test_blocked_path_re_matches_upgrade_cgi(self):
        self.assertIsNotNone(_BLOCKED_PATH_RE.search("/upgrade.cgi"))

    def test_blocked_path_re_does_not_match_safe_path(self):
        self.assertIsNone(_BLOCKED_PATH_RE.search("/html/ssmp/wlan/wlan.asp"))

    def test_crawlable_types(self):
        self.assertIn("text/html", CRAWLABLE_TYPES)
        self.assertIn("application/javascript", CRAWLABLE_TYPES)
        self.assertIn("text/css", CRAWLABLE_TYPES)
        self.assertIn("application/json", CRAWLABLE_TYPES)
        self.assertIsInstance(CRAWLABLE_TYPES, set)

    def test_login_markers(self):
        self.assertIn("txt_Username", _LOGIN_MARKERS)
        self.assertIn("txt_Password", _LOGIN_MARKERS)
        self.assertIn("loginbutton", _LOGIN_MARKERS)


if __name__ == "__main__":
    unittest.main()
