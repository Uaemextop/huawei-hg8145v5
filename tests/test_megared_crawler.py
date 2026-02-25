"""
Tests for megared_crawler.py — Megared.net.mx Index File Finder.

These tests validate the URL normalisation, link extraction, index-file
detection, reachability checks, HTTP rejection handling, and report-
generation logic WITHOUT making real HTTP requests.
"""

import json
import socket
import subprocess
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock
from dataclasses import asdict

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from megared_crawler import (
    BASE_DOMAIN,
    INDEX_FILENAMES,
    KNOWN_SUBDOMAINS,
    COMMON_PATHS,
    _ALTERNATE_USER_AGENTS,
    IndexFileResult,
    CrawlReport,
    MegaredCrawler,
    extract_links,
    extract_title,
    is_index_file,
    normalise_url,
    dns_resolves,
    ping_host,
    tcp_connect,
    http_head_check,
    check_host_reachable,
    parse_retry_after,
    handle_http_rejection,
    try_alternate_scheme,
    is_connection_reset,
    retry_on_connection_reset,
)


class TestNormaliseUrl(unittest.TestCase):
    """Test URL normalisation and domain filtering."""

    def test_absolute_same_domain(self):
        result = normalise_url(
            "https://megared.net.mx/page.html",
            "https://megared.net.mx/",
            "https://megared.net.mx",
        )
        self.assertEqual(result, "https://megared.net.mx/page.html")

    def test_absolute_subdomain(self):
        result = normalise_url(
            "https://acsvip.megared.net.mx/service",
            "https://megared.net.mx/",
            "https://megared.net.mx",
        )
        self.assertEqual(result, "https://acsvip.megared.net.mx/service")

    def test_relative_path(self):
        result = normalise_url(
            "/login.html",
            "https://megared.net.mx/",
            "https://megared.net.mx",
        )
        self.assertEqual(result, "https://megared.net.mx/login.html")

    def test_rejects_external_domain(self):
        result = normalise_url(
            "https://google.com/",
            "https://megared.net.mx/",
            "https://megared.net.mx",
        )
        self.assertIsNone(result)

    def test_rejects_javascript_uri(self):
        result = normalise_url(
            "javascript:void(0)",
            "https://megared.net.mx/",
            "https://megared.net.mx",
        )
        self.assertIsNone(result)

    def test_rejects_mailto(self):
        result = normalise_url(
            "mailto:admin@megared.net.mx",
            "https://megared.net.mx/",
            "https://megared.net.mx",
        )
        self.assertIsNone(result)

    def test_rejects_fragment_only(self):
        result = normalise_url(
            "#section",
            "https://megared.net.mx/",
            "https://megared.net.mx",
        )
        self.assertIsNone(result)

    def test_rejects_empty(self):
        result = normalise_url("", "https://megared.net.mx/", "https://megared.net.mx")
        self.assertIsNone(result)

    def test_strips_fragment(self):
        result = normalise_url(
            "https://megared.net.mx/page.html#top",
            "https://megared.net.mx/",
            "https://megared.net.mx",
        )
        self.assertEqual(result, "https://megared.net.mx/page.html")

    def test_preserves_query_string(self):
        result = normalise_url(
            "/search?q=test",
            "https://megared.net.mx/",
            "https://megared.net.mx",
        )
        self.assertEqual(result, "https://megared.net.mx/search?q=test")


class TestIsIndexFile(unittest.TestCase):
    """Test index file detection."""

    def test_root_path(self):
        self.assertTrue(is_index_file("https://megared.net.mx/"))

    def test_index_html(self):
        self.assertTrue(is_index_file("https://megared.net.mx/index.html"))

    def test_index_php(self):
        self.assertTrue(is_index_file("https://megared.net.mx/index.php"))

    def test_index_asp(self):
        self.assertTrue(is_index_file("https://megared.net.mx/admin/index.asp"))

    def test_default_aspx(self):
        self.assertTrue(is_index_file("https://megared.net.mx/Default.aspx"))

    def test_non_index_file(self):
        self.assertFalse(is_index_file("https://megared.net.mx/about.html"))

    def test_non_index_cgi(self):
        self.assertFalse(is_index_file("https://megared.net.mx/login.cgi"))

    def test_main_asp(self):
        self.assertTrue(is_index_file("https://megared.net.mx/main.asp"))

    def test_home_html(self):
        self.assertTrue(is_index_file("https://megared.net.mx/home.html"))

    def test_index_jhtml(self):
        self.assertTrue(is_index_file("https://megared.net.mx/index.jhtml"))

    def test_index_phtml(self):
        self.assertTrue(is_index_file("https://megared.net.mx/index.phtml"))

    def test_index_jsf(self):
        self.assertTrue(is_index_file("https://megared.net.mx/index.jsf"))

    def test_index_jhtml_in_firmware(self):
        self.assertTrue(is_index_file("https://megared.net.mx/firmware/index.jhtml"))

    def test_empty_path(self):
        self.assertTrue(is_index_file("https://megared.net.mx"))


class TestExtractTitle(unittest.TestCase):
    """Test HTML title extraction."""

    def test_basic_title(self):
        html = "<html><head><title>Megared Portal</title></head><body></body></html>"
        self.assertEqual(extract_title(html), "Megared Portal")

    def test_no_title(self):
        html = "<html><head></head><body>No title here</body></html>"
        self.assertEqual(extract_title(html), "")

    def test_empty_title(self):
        html = "<html><head><title></title></head><body></body></html>"
        self.assertEqual(extract_title(html), "")

    def test_whitespace_title(self):
        html = "<html><head><title>  Megared  </title></head><body></body></html>"
        self.assertEqual(extract_title(html), "Megared")


class TestExtractLinks(unittest.TestCase):
    """Test link extraction from HTML content."""

    def test_anchor_href(self):
        html = '<html><body><a href="/login.html">Login</a></body></html>'
        links = extract_links(html, "https://megared.net.mx/")
        self.assertIn("https://megared.net.mx/login.html", links)

    def test_script_src(self):
        html = '<html><head><script src="/js/app.js"></script></head><body></body></html>'
        links = extract_links(html, "https://megared.net.mx/")
        self.assertIn("https://megared.net.mx/js/app.js", links)

    def test_img_src(self):
        html = '<html><body><img src="/images/logo.png"></body></html>'
        links = extract_links(html, "https://megared.net.mx/")
        self.assertIn("https://megared.net.mx/images/logo.png", links)

    def test_external_link_filtered(self):
        html = '<html><body><a href="https://google.com/">Google</a></body></html>'
        links = extract_links(html, "https://megared.net.mx/")
        self.assertEqual(len([l for l in links if "google" in l]), 0)

    def test_subdomain_link_kept(self):
        html = '<html><body><a href="https://acsvip.megared.net.mx/">ACS</a></body></html>'
        links = extract_links(html, "https://megared.net.mx/")
        self.assertIn("https://acsvip.megared.net.mx/", links)

    def test_meta_refresh(self):
        html = '<html><head><meta http-equiv="refresh" content="0;url=/portal/"></head></html>'
        links = extract_links(html, "https://megared.net.mx/")
        self.assertIn("https://megared.net.mx/portal/", links)

    def test_form_action(self):
        html = '<html><body><form action="/api/login"></form></body></html>'
        links = extract_links(html, "https://megared.net.mx/")
        self.assertIn("https://megared.net.mx/api/login", links)

    def test_inline_script_paths(self):
        html = """<html><body><script>
        var apiUrl = '/api/status';
        </script></body></html>"""
        links = extract_links(html, "https://megared.net.mx/")
        self.assertIn("https://megared.net.mx/api/status", links)


class TestIndexFileResult(unittest.TestCase):
    """Test IndexFileResult data class."""

    def test_creation(self):
        result = IndexFileResult(
            url="https://megared.net.mx/index.html",
            status_code=200,
            content_type="text/html",
            content_length=1234,
            server="nginx",
            title="Megared Portal",
        )
        self.assertEqual(result.url, "https://megared.net.mx/index.html")
        self.assertEqual(result.status_code, 200)
        self.assertNotEqual(result.timestamp, "")

    def test_with_redirect(self):
        result = IndexFileResult(
            url="https://megared.net.mx/",
            status_code=200,
            content_type="text/html",
            content_length=5678,
            server="Apache",
            title="Home",
            redirect_url="https://www.megared.net.mx/",
        )
        self.assertEqual(result.redirect_url, "https://www.megared.net.mx/")


class TestCrawlReport(unittest.TestCase):
    """Test CrawlReport data class and serialization."""

    def test_empty_report(self):
        report = CrawlReport()
        d = report.to_dict()
        self.assertEqual(d["total_index_files"], 0)
        self.assertEqual(d["total_urls_discovered"], 0)
        self.assertEqual(d["target_domain"], BASE_DOMAIN)

    def test_report_with_results(self):
        report = CrawlReport()
        report.index_files_found.append(IndexFileResult(
            url="https://megared.net.mx/index.html",
            status_code=200,
            content_type="text/html",
            content_length=100,
            server="nginx",
            title="Test",
        ))
        report.urls_visited = 5
        d = report.to_dict()
        self.assertEqual(d["total_index_files"], 1)
        self.assertEqual(d["urls_visited"], 5)

    def test_report_save(self):
        import tempfile
        report = CrawlReport()
        report.index_files_found.append(IndexFileResult(
            url="https://megared.net.mx/index.html",
            status_code=200,
            content_type="text/html",
            content_length=100,
            server="nginx",
            title="Test",
        ))
        with tempfile.TemporaryDirectory() as tmpdir:
            path = report.save(Path(tmpdir))
            self.assertTrue(path.exists())
            data = json.loads(path.read_text())
            self.assertEqual(data["total_index_files"], 1)


class TestMegaredCrawlerInit(unittest.TestCase):
    """Test MegaredCrawler initialization."""

    def test_default_init(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            crawler = MegaredCrawler(output_dir=Path(tmpdir))
            self.assertEqual(crawler.max_depth, 2)
            self.assertEqual(crawler.max_pages, 200)
            self.assertEqual(crawler.delay, 0.5)
            self.assertFalse(crawler.include_ports)

    def test_custom_init(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            crawler = MegaredCrawler(
                output_dir=Path(tmpdir),
                max_depth=5,
                max_pages=1000,
                delay=1.0,
                include_ports=True,
            )
            self.assertEqual(crawler.max_depth, 5)
            self.assertEqual(crawler.max_pages, 1000)
            self.assertEqual(crawler.delay, 1.0)
            self.assertTrue(crawler.include_ports)


class TestMegaredCrawlerUrlKey(unittest.TestCase):
    """Test URL deduplication key generation."""

    def test_strips_query(self):
        k1 = MegaredCrawler._url_key("https://megared.net.mx/page?v=1")
        k2 = MegaredCrawler._url_key("https://megared.net.mx/page?v=2")
        self.assertEqual(k1, k2)

    def test_different_paths(self):
        k1 = MegaredCrawler._url_key("https://megared.net.mx/a")
        k2 = MegaredCrawler._url_key("https://megared.net.mx/b")
        self.assertNotEqual(k1, k2)

    def test_different_schemes(self):
        k1 = MegaredCrawler._url_key("http://megared.net.mx/page")
        k2 = MegaredCrawler._url_key("https://megared.net.mx/page")
        self.assertNotEqual(k1, k2)


class TestConfigConstants(unittest.TestCase):
    """Test configuration constants are properly defined."""

    def test_base_domain(self):
        self.assertEqual(BASE_DOMAIN, "megared.net.mx")

    def test_known_subdomains_not_empty(self):
        self.assertGreater(len(KNOWN_SUBDOMAINS), 0)

    def test_known_subdomains_contain_base(self):
        self.assertIn("megared.net.mx", KNOWN_SUBDOMAINS)

    def test_acsvip_subdomain_present(self):
        self.assertIn("acsvip.megared.net.mx", KNOWN_SUBDOMAINS)

    def test_index_filenames_not_empty(self):
        self.assertGreater(len(INDEX_FILENAMES), 0)

    def test_index_filenames_contain_basics(self):
        self.assertIn("index.html", INDEX_FILENAMES)
        self.assertIn("index.php", INDEX_FILENAMES)
        self.assertIn("index.asp", INDEX_FILENAMES)

    def test_index_filenames_contain_jhtml(self):
        self.assertIn("index.jhtml", INDEX_FILENAMES)

    def test_index_filenames_contain_phtml(self):
        self.assertIn("index.phtml", INDEX_FILENAMES)

    def test_index_filenames_contain_jsf(self):
        self.assertIn("index.jsf", INDEX_FILENAMES)

    def test_index_filenames_contain_jspx(self):
        self.assertIn("index.jspx", INDEX_FILENAMES)

    def test_common_paths_contain_root(self):
        self.assertIn("/", COMMON_PATHS)

    def test_common_paths_contain_cwmp(self):
        self.assertIn("/service/cwmp", COMMON_PATHS)

    def test_common_paths_contain_firmware(self):
        self.assertIn("/firmware/", COMMON_PATHS)

    def test_common_paths_contain_firmware_update(self):
        self.assertIn("/firmware/update/", COMMON_PATHS)

    def test_common_paths_contain_download(self):
        self.assertIn("/download/", COMMON_PATHS)

    def test_common_paths_contain_fw(self):
        self.assertIn("/fw/", COMMON_PATHS)

    def test_common_paths_contain_acs(self):
        self.assertIn("/acs/", COMMON_PATHS)


# ===================================================================
# Reachability & ping-blocked host handling
# ===================================================================

class TestDnsResolves(unittest.TestCase):
    """Test DNS pre-resolution check."""

    @patch("megared_crawler.socket.getaddrinfo", return_value=[(2, 1, 6, '', ('1.2.3.4', 0))])
    def test_resolves(self, mock_dns):
        self.assertTrue(dns_resolves("megared.net.mx"))

    @patch("megared_crawler.socket.getaddrinfo", side_effect=socket.gaierror("not found"))
    def test_does_not_resolve(self, mock_dns):
        self.assertFalse(dns_resolves("nonexistent.megared.net.mx"))

    @patch("megared_crawler.socket.getaddrinfo", side_effect=OSError("network"))
    def test_os_error(self, mock_dns):
        self.assertFalse(dns_resolves("megared.net.mx"))


class TestPingHost(unittest.TestCase):
    """Test ICMP ping wrapper."""

    @patch("megared_crawler.subprocess.run")
    def test_ping_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        self.assertTrue(ping_host("megared.net.mx"))

    @patch("megared_crawler.subprocess.run")
    def test_ping_failure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        self.assertFalse(ping_host("megared.net.mx"))

    @patch("megared_crawler.subprocess.run", side_effect=FileNotFoundError)
    def test_ping_command_missing(self, mock_run):
        self.assertFalse(ping_host("megared.net.mx"))

    @patch("megared_crawler.subprocess.run",
           side_effect=subprocess.TimeoutExpired("ping", 5))
    def test_ping_timeout(self, mock_run):
        import subprocess
        self.assertFalse(ping_host("megared.net.mx"))


class TestTcpConnect(unittest.TestCase):
    """Test raw TCP connection probe."""

    @patch("megared_crawler.socket.create_connection")
    def test_tcp_success(self, mock_conn):
        mock_conn.return_value.__enter__ = MagicMock()
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        self.assertTrue(tcp_connect("megared.net.mx", 443))

    @patch("megared_crawler.socket.create_connection",
           side_effect=socket.timeout("timed out"))
    def test_tcp_timeout(self, mock_conn):
        import socket
        self.assertFalse(tcp_connect("megared.net.mx", 443))

    @patch("megared_crawler.socket.create_connection",
           side_effect=ConnectionRefusedError)
    def test_tcp_refused(self, mock_conn):
        self.assertFalse(tcp_connect("megared.net.mx", 443))


class TestHttpHeadCheck(unittest.TestCase):
    """Test HTTP HEAD reachability check."""

    def _mock_session(self, status=200, server="nginx", url="https://megared.net.mx/"):
        session = MagicMock()
        resp = MagicMock()
        resp.status_code = status
        resp.headers = {"Server": server}
        resp.url = url
        session.head.return_value = resp
        return session

    def test_reachable(self):
        session = self._mock_session()
        result = http_head_check("megared.net.mx", session)
        self.assertTrue(result["reachable"])
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["server"], "nginx")

    def test_unreachable(self):
        import requests
        session = MagicMock()
        session.head.side_effect = requests.ConnectionError("refused")
        result = http_head_check("megared.net.mx", session)
        self.assertFalse(result["reachable"])


class TestCheckHostReachable(unittest.TestCase):
    """Test multi-strategy reachability (DNS → ping → TCP → HTTP)."""

    @patch("megared_crawler.http_head_check")
    @patch("megared_crawler.tcp_connect")
    @patch("megared_crawler.ping_host")
    @patch("megared_crawler.dns_resolves", return_value=True)
    def test_ping_blocked_tcp_works(self, mock_dns, mock_ping, mock_tcp, mock_http):
        """Host blocks ICMP but TCP 443 is open."""
        mock_ping.return_value = False
        mock_tcp.side_effect = lambda h, p, **kw: p == 443
        mock_http.return_value = {"reachable": True, "status": 200,
                                   "server": "nginx", "url": "https://megared.net.mx/",
                                   "method": "HEAD", "scheme": "https"}
        result = check_host_reachable("megared.net.mx")
        self.assertTrue(result["reachable"])
        self.assertFalse(result["ping"])
        self.assertTrue(result["tcp_443"])
        self.assertTrue(result["dns"])

    @patch("megared_crawler.http_head_check")
    @patch("megared_crawler.tcp_connect")
    @patch("megared_crawler.ping_host")
    @patch("megared_crawler.dns_resolves", return_value=True)
    def test_all_fail(self, mock_dns, mock_ping, mock_tcp, mock_http):
        """Completely unreachable host (DNS resolves but nothing open)."""
        mock_ping.return_value = False
        mock_tcp.return_value = False
        mock_http.return_value = {"reachable": False, "status": 0,
                                   "server": "", "url": "",
                                   "method": "HEAD", "scheme": ""}
        result = check_host_reachable("nonexistent.megared.net.mx")
        self.assertFalse(result["reachable"])

    @patch("megared_crawler.http_head_check")
    @patch("megared_crawler.tcp_connect")
    @patch("megared_crawler.ping_host")
    @patch("megared_crawler.dns_resolves", return_value=True)
    def test_ping_succeeds(self, mock_dns, mock_ping, mock_tcp, mock_http):
        mock_ping.return_value = True
        mock_tcp.return_value = True
        mock_http.return_value = {"reachable": True, "status": 200,
                                   "server": "", "url": "https://megared.net.mx/",
                                   "method": "HEAD", "scheme": "https"}
        result = check_host_reachable("megared.net.mx")
        self.assertTrue(result["reachable"])
        self.assertTrue(result["ping"])
        self.assertEqual(result["method"], "ping")

    @patch("megared_crawler.dns_resolves", return_value=False)
    def test_dns_fails_skips_everything(self, mock_dns):
        """Host that does not resolve in DNS is immediately unreachable."""
        result = check_host_reachable("nope.megared.net.mx")
        self.assertFalse(result["reachable"])
        self.assertFalse(result.get("dns", False))
        self.assertEqual(result["method"], "")


# ===================================================================
# HTTP rejection handling
# ===================================================================

class TestParseRetryAfter(unittest.TestCase):
    """Test Retry-After header parsing."""

    def test_numeric_seconds(self):
        self.assertEqual(parse_retry_after("120"), 120.0)

    def test_clamp_min(self):
        self.assertEqual(parse_retry_after("0"), 1.0)

    def test_clamp_max(self):
        self.assertEqual(parse_retry_after("9999"), 300.0)

    def test_invalid_falls_back(self):
        self.assertEqual(parse_retry_after("not-a-date-or-number"), 30.0)


class TestHandleHttpRejection(unittest.TestCase):
    """Test HTTP rejection handler with retries."""

    def _mock_response(self, status, headers=None, url="https://megared.net.mx/"):
        resp = MagicMock()
        resp.status_code = status
        resp.headers = headers or {}
        resp.url = url
        return resp

    def test_429_retry_success(self):
        """Rate limited → wait → retry succeeds."""
        import requests
        rejected = self._mock_response(429, {"Retry-After": "1"})
        success = self._mock_response(200)
        session = MagicMock()
        session.get.return_value = success

        result = handle_http_rejection(
            rejected, "https://megared.net.mx/", session, attempt=0, max_retries=2,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 200)

    def test_403_strip_query(self):
        """403 with query → retries without query."""
        rejected = self._mock_response(403)
        success = self._mock_response(200)
        session = MagicMock()
        session.get.return_value = success

        result = handle_http_rejection(
            rejected, "https://megared.net.mx/page?secret=1",
            session, attempt=0, max_retries=2,
        )
        self.assertIsNotNone(result)
        session.get.assert_called_once()

    def test_403_add_trailing_slash(self):
        """403 without query → retries with trailing slash."""
        rejected = self._mock_response(403)
        success = self._mock_response(200)
        session = MagicMock()
        session.get.return_value = success

        result = handle_http_rejection(
            rejected, "https://megared.net.mx/admin",
            session, attempt=0, max_retries=2,
        )
        self.assertIsNotNone(result)
        call_url = session.get.call_args[0][0]
        self.assertTrue(call_url.endswith("/"))

    def test_401_skipped(self):
        """401 Unauthorized is not retried."""
        rejected = self._mock_response(401)
        session = MagicMock()

        result = handle_http_rejection(
            rejected, "https://megared.net.mx/", session,
        )
        self.assertIsNone(result)
        session.get.assert_not_called()

    def test_max_retries_exhausted(self):
        """Returns None when max retries reached."""
        rejected = self._mock_response(503)
        session = MagicMock()

        result = handle_http_rejection(
            rejected, "https://megared.net.mx/", session,
            attempt=5, max_retries=2,
        )
        self.assertIsNone(result)


class TestTryAlternateScheme(unittest.TestCase):
    """Test HTTP ↔ HTTPS scheme fallback."""

    def test_https_to_http_fallback(self):
        import requests
        success = MagicMock()
        success.status_code = 200
        session = MagicMock()
        session.get.return_value = success

        result = try_alternate_scheme("https://megared.net.mx/page", session)
        self.assertIsNotNone(result)
        call_url = session.get.call_args[0][0]
        self.assertTrue(call_url.startswith("http://"))

    def test_http_to_https_fallback(self):
        success = MagicMock()
        success.status_code = 200
        session = MagicMock()
        session.get.return_value = success

        result = try_alternate_scheme("http://megared.net.mx/page", session)
        self.assertIsNotNone(result)
        call_url = session.get.call_args[0][0]
        self.assertTrue(call_url.startswith("https://"))

    def test_fallback_fails(self):
        import requests
        session = MagicMock()
        session.get.side_effect = requests.ConnectionError("refused")

        result = try_alternate_scheme("https://megared.net.mx/page", session)
        self.assertIsNone(result)

    def test_fallback_returns_error_status(self):
        fail = MagicMock()
        fail.status_code = 500
        session = MagicMock()
        session.get.return_value = fail

        result = try_alternate_scheme("https://megared.net.mx/page", session)
        self.assertIsNone(result)


# ===================================================================
# Huawei router User-Agents & connection-reset resilience
# ===================================================================

class TestAlternateUserAgents(unittest.TestCase):
    """Test the User-Agent pool includes Huawei router UAs."""

    def test_pool_not_empty(self):
        self.assertGreater(len(_ALTERNATE_USER_AGENTS), 0)

    def test_contains_browser_ua(self):
        chrome = [ua for ua in _ALTERNATE_USER_AGENTS if "Chrome" in ua]
        self.assertGreater(len(chrome), 0)

    def test_contains_huawei_hg8145v5(self):
        hg8145 = [ua for ua in _ALTERNATE_USER_AGENTS if "HG8145V5" in ua]
        self.assertGreater(len(hg8145), 0, "Pool must include HG8145V5 UA")

    def test_contains_huawei_cwmp(self):
        cwmp = [ua for ua in _ALTERNATE_USER_AGENTS if "CWMP" in ua]
        self.assertGreater(len(cwmp), 0, "Pool must include CWMP UAs")

    def test_contains_huawei_hg8245(self):
        hg8245 = [ua for ua in _ALTERNATE_USER_AGENTS
                   if "HG8245" in ua or "HG8245H" in ua]
        self.assertGreater(len(hg8245), 0, "Pool must include HG8245 UA")

    def test_contains_echolife(self):
        echolife = [ua for ua in _ALTERNATE_USER_AGENTS if "EchoLife" in ua]
        self.assertGreater(len(echolife), 0, "Pool must include EchoLife UA")

    def test_contains_generic_huawei_gw(self):
        gw = [ua for ua in _ALTERNATE_USER_AGENTS if "HuaweiHomeGateway" in ua]
        self.assertGreater(len(gw), 0, "Pool must include generic gateway UA")

    def test_all_strings(self):
        for ua in _ALTERNATE_USER_AGENTS:
            self.assertIsInstance(ua, str)
            self.assertGreater(len(ua), 0)


class TestIsConnectionReset(unittest.TestCase):
    """Test connection-reset detection across exception chains."""

    def test_direct_connection_reset_error(self):
        exc = ConnectionResetError(104, "Connection reset by peer")
        self.assertTrue(is_connection_reset(exc))

    def test_broken_pipe(self):
        exc = BrokenPipeError("Broken pipe")
        self.assertTrue(is_connection_reset(exc))

    def test_wrapped_in_requests(self):
        import requests
        inner = ConnectionResetError(104, "Connection reset by peer")
        outer = requests.ConnectionError(inner)
        outer.__cause__ = inner
        self.assertTrue(is_connection_reset(outer))

    def test_message_contains_reset(self):
        exc = OSError("Connection reset by peer")
        self.assertTrue(is_connection_reset(exc))

    def test_message_contains_econnreset(self):
        exc = OSError("[Errno 104] ECONNRESET")
        self.assertTrue(is_connection_reset(exc))

    def test_unrelated_error(self):
        exc = ValueError("something else")
        self.assertFalse(is_connection_reset(exc))

    def test_timeout_is_not_reset(self):
        exc = TimeoutError("timed out")
        self.assertFalse(is_connection_reset(exc))


class TestRetryOnConnectionReset(unittest.TestCase):
    """Test multi-strategy connection-reset retry logic."""

    @patch("megared_crawler.try_alternate_scheme", return_value=None)
    @patch("megared_crawler.time.sleep")
    def test_retry_succeeds_on_first_attempt(self, mock_sleep, mock_alt):
        success = MagicMock()
        success.status_code = 200
        session = MagicMock()
        session.get.return_value = success
        session.headers = {}

        result = retry_on_connection_reset(
            "https://megared.net.mx/", session, max_retries=3,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 200)
        mock_sleep.assert_called()

    @patch("megared_crawler.build_session")
    @patch("megared_crawler.try_alternate_scheme", return_value=None)
    @patch("megared_crawler.time.sleep")
    def test_all_retries_exhausted(self, mock_sleep, mock_alt, mock_build):
        import requests as req
        session = MagicMock()
        session.get.side_effect = req.ConnectionError("reset by peer")
        session.headers = {}
        fresh = MagicMock()
        fresh.get.side_effect = req.ConnectionError("reset by peer")
        fresh.headers = {}
        mock_build.return_value = fresh

        result = retry_on_connection_reset(
            "https://megared.net.mx/", session, max_retries=2,
        )
        self.assertIsNone(result)

    @patch("megared_crawler.try_alternate_scheme")
    @patch("megared_crawler.time.sleep")
    def test_alternate_scheme_succeeds(self, mock_sleep, mock_alt):
        import requests as req
        session = MagicMock()
        session.get.side_effect = req.ConnectionError("reset by peer")
        session.headers = {}
        alt_resp = MagicMock()
        alt_resp.status_code = 200
        mock_alt.return_value = alt_resp

        result = retry_on_connection_reset(
            "https://megared.net.mx/", session, max_retries=3,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 200)

    @patch("megared_crawler.try_alternate_scheme", return_value=None)
    @patch("megared_crawler.time.sleep")
    def test_ua_rotated_on_each_attempt(self, mock_sleep, mock_alt):
        """Verify the User-Agent header changes between retries."""
        success = MagicMock()
        success.status_code = 200
        headers_seen = []

        session = MagicMock()
        session.headers = {}

        def capture_get(*a, **kw):
            headers_seen.append(session.headers.get("User-Agent", ""))
            return success

        session.get.side_effect = capture_get

        retry_on_connection_reset(
            "https://megared.net.mx/", session, max_retries=1,
        )
        self.assertGreater(len(headers_seen), 0)
        self.assertIn(headers_seen[0], _ALTERNATE_USER_AGENTS)


if __name__ == "__main__":
    unittest.main()
