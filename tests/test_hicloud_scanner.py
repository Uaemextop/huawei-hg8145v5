"""Tests for hicloud_scanner.py — Huawei HiCloud Firmware Server Scanner."""

import json
import os
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hicloud_scanner import (
    TARGET_HOST,
    BASE_URL,
    HICLOUD_HOSTS,
    DEFAULT_TCP_PORTS,
    DEFAULT_UDP_PORTS,
    USER_AGENTS,
    TDS_PRODUCTS,
    TDS_SERIES,
    TDS_GROUPS,
    TDS_VERSIONS,
    COMMON_PATHS,
    INDEX_FILENAMES,
    HG8145V5_FIRMWARE_FILES,
    GITHUB_WORDLISTS,
    PortResult,
    HttpProbeResult,
    FirmwareCandidate,
    NmapResult,
    ScanReport,
    resolve_host,
    scan_tcp_port,
    scan_udp_port,
    http_probe,
    probe_url_multi_method,
    discover_paths,
    discover_index_files,
    search_firmware_files,
    download_wordlists,
    load_wordlist_paths,
    run_nmap_scan,
    _nmap_available,
    _parse_nmap_xml,
)


class TestTargetConfig(unittest.TestCase):
    """Test target configuration constants."""

    def test_target_host(self):
        self.assertEqual(TARGET_HOST, "update.hicloud.com")

    def test_base_url_contains_tds(self):
        self.assertIn("/TDS/data/files/", BASE_URL)

    def test_base_url_port_8180(self):
        self.assertIn(":8180", BASE_URL)

    def test_base_url_p9_s115(self):
        """Base URL should contain the product/series from the issue."""
        self.assertIn("/p9/s115/G345/", BASE_URL)

    def test_hicloud_hosts_not_empty(self):
        self.assertGreater(len(HICLOUD_HOSTS), 5)

    def test_hicloud_hosts_includes_target(self):
        self.assertIn(TARGET_HOST, HICLOUD_HOSTS)

    def test_hicloud_hosts_includes_dbankcloud(self):
        self.assertIn("update.dbankcloud.com", HICLOUD_HOSTS)


class TestPorts(unittest.TestCase):
    """Test port lists."""

    def test_tcp_ports_include_8180(self):
        self.assertIn(8180, DEFAULT_TCP_PORTS)

    def test_tcp_ports_include_http(self):
        self.assertIn(80, DEFAULT_TCP_PORTS)
        self.assertIn(443, DEFAULT_TCP_PORTS)

    def test_tcp_ports_include_tr069(self):
        self.assertIn(7547, DEFAULT_TCP_PORTS)

    def test_tcp_ports_include_alt_http(self):
        self.assertIn(8080, DEFAULT_TCP_PORTS)
        self.assertIn(8443, DEFAULT_TCP_PORTS)

    def test_udp_ports_include_dns(self):
        self.assertIn(53, DEFAULT_UDP_PORTS)


class TestUserAgents(unittest.TestCase):
    """Test User-Agent list."""

    def test_not_empty(self):
        self.assertGreater(len(USER_AGENTS), 5)

    def test_huawei_home_gateway_ua(self):
        self.assertIn("HuaweiHomeGateway", USER_AGENTS)

    def test_hw_ftth_ua(self):
        self.assertIn("HW-FTTH", USER_AGENTS)

    def test_curl_ua(self):
        curl = [ua for ua in USER_AGENTS if "curl" in ua]
        self.assertGreater(len(curl), 0)

    def test_browser_ua(self):
        chrome = [ua for ua in USER_AGENTS if "Chrome" in ua]
        self.assertGreater(len(chrome), 0)


class TestTDSPatterns(unittest.TestCase):
    """Test TDS URL path patterns."""

    def test_products_include_p9(self):
        self.assertIn("p9", TDS_PRODUCTS)

    def test_series_include_s115(self):
        self.assertIn("s115", TDS_SERIES)

    def test_series_include_s117(self):
        """s117 could be HG8145V5-12 variant."""
        self.assertIn("s117", TDS_SERIES)

    def test_groups_include_g345(self):
        self.assertIn("G345", TDS_GROUPS)

    def test_versions_include_v10149(self):
        self.assertIn("v10149", TDS_VERSIONS)


class TestCommonPaths(unittest.TestCase):
    """Test common paths for directory discovery."""

    def test_not_empty(self):
        self.assertGreater(len(COMMON_PATHS), 20)

    def test_includes_tds_path(self):
        self.assertIn("/TDS/", COMMON_PATHS)

    def test_includes_firmware_path(self):
        self.assertIn("/firmware/", COMMON_PATHS)

    def test_includes_hg8145v5_path(self):
        hg = [p for p in COMMON_PATHS if "HG8145V5" in p]
        self.assertGreater(len(hg), 0)

    def test_includes_full_tds_path(self):
        full = [p for p in COMMON_PATHS if "v10149" in p]
        self.assertGreater(len(full), 0)


class TestIndexFilenames(unittest.TestCase):
    """Test index file discovery names."""

    def test_not_empty(self):
        self.assertGreater(len(INDEX_FILENAMES), 20)

    def test_includes_index_html(self):
        self.assertIn("index.html", INDEX_FILENAMES)

    def test_includes_index_xml(self):
        self.assertIn("index.xml", INDEX_FILENAMES)

    def test_includes_filelist(self):
        self.assertIn("filelist.xml", INDEX_FILENAMES)

    def test_includes_firmware_json(self):
        self.assertIn("firmware.json", INDEX_FILENAMES)

    def test_includes_update_xml(self):
        self.assertIn("update.xml", INDEX_FILENAMES)


class TestFirmwareFiles(unittest.TestCase):
    """Test HG8145V5 firmware filename list."""

    def test_not_empty(self):
        self.assertGreater(len(HG8145V5_FIRMWARE_FILES), 20)

    def test_hg8145v5_bin(self):
        self.assertIn("HG8145V5.bin", HG8145V5_FIRMWARE_FILES)

    def test_hg8145v5_12_bin(self):
        self.assertIn("HG8145V5-12.bin", HG8145V5_FIRMWARE_FILES)

    def test_eg8145v5_spc340(self):
        self.assertIn("EG8145V5-V500R022C00SPC340B019.bin",
                       HG8145V5_FIRMWARE_FILES)

    def test_hg8145v5_12_variants(self):
        v12 = [f for f in HG8145V5_FIRMWARE_FILES if "HG8145V5-12" in f]
        self.assertGreater(len(v12), 2, "Should have multiple HG8145V5-12 variants")

    def test_compressed_variants(self):
        gz = [f for f in HG8145V5_FIRMWARE_FILES if f.endswith(".gz")]
        self.assertGreater(len(gz), 0)


class TestGitHubWordlists(unittest.TestCase):
    """Test GitHub wordlist metadata."""

    def test_has_description(self):
        self.assertIn("description", GITHUB_WORDLISTS)

    def test_has_sources(self):
        self.assertIn("sources", GITHUB_WORDLISTS)
        self.assertGreater(len(GITHUB_WORDLISTS["sources"]), 0)

    def test_has_paths(self):
        self.assertIn("paths", GITHUB_WORDLISTS)
        self.assertGreater(len(GITHUB_WORDLISTS["paths"]), 30)

    def test_includes_huawei_paths(self):
        paths = GITHUB_WORDLISTS["paths"]
        huawei = [p for p in paths if "TDS" in p or "HMS" in p or "EMUI" in p]
        self.assertGreater(len(huawei), 0)


class TestPortResult(unittest.TestCase):
    """Test PortResult dataclass."""

    def test_to_dict(self):
        pr = PortResult(host="1.2.3.4", port=8180, protocol="tcp",
                        state="open", banner="HTTP/1.1", latency_ms=10.5)
        d = pr.to_dict()
        self.assertEqual(d["port"], 8180)
        self.assertEqual(d["state"], "open")
        self.assertEqual(d["protocol"], "tcp")

    def test_closed_port(self):
        pr = PortResult(host="1.2.3.4", port=22, protocol="tcp", state="closed")
        self.assertEqual(pr.state, "closed")

    def test_filtered_port(self):
        pr = PortResult(host="1.2.3.4", port=445, protocol="tcp", state="filtered")
        self.assertEqual(pr.state, "filtered")


class TestHttpProbeResult(unittest.TestCase):
    """Test HttpProbeResult dataclass."""

    def test_to_dict_minimal(self):
        r = HttpProbeResult(url="http://example.com", method="GET",
                            user_agent="test")
        d = r.to_dict()
        self.assertEqual(d["url"], "http://example.com")
        self.assertEqual(d["method"], "GET")

    def test_to_dict_with_status(self):
        r = HttpProbeResult(url="http://example.com", method="GET",
                            user_agent="test", status_code=200,
                            server="nginx", content_type="text/html")
        d = r.to_dict()
        self.assertEqual(d["status_code"], 200)
        self.assertEqual(d["server"], "nginx")

    def test_to_dict_with_error(self):
        r = HttpProbeResult(url="http://example.com", method="GET",
                            user_agent="test", error="Connection refused")
        d = r.to_dict()
        self.assertIn("error", d)


class TestFirmwareCandidate(unittest.TestCase):
    """Test FirmwareCandidate dataclass."""

    def test_to_dict(self):
        fc = FirmwareCandidate(
            url="http://example.com/fw.bin",
            filename="fw.bin",
            status_code=200,
            content_type="application/octet-stream",
            content_length=50_000_000,
            is_downloadable=True,
        )
        d = fc.to_dict()
        self.assertEqual(d["filename"], "fw.bin")
        self.assertTrue(d["is_downloadable"])
        self.assertEqual(d["content_length"], 50_000_000)

    def test_not_downloadable(self):
        fc = FirmwareCandidate(url="http://example.com/fw.bin",
                               filename="fw.bin", status_code=404)
        self.assertFalse(fc.is_downloadable)


class TestScanReport(unittest.TestCase):
    """Test ScanReport dataclass."""

    def test_to_dict(self):
        r = ScanReport(
            timestamp="2025-01-01T00:00:00Z",
            target=TARGET_HOST,
            base_url=BASE_URL,
        )
        d = r.to_dict()
        self.assertEqual(d["target"], TARGET_HOST)
        self.assertIn("http_probes", d)
        self.assertIn("firmware_candidates", d)

    def test_save_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            r = ScanReport(
                timestamp="2025-01-01T00:00:00Z",
                target=TARGET_HOST,
            )
            path = r.save(Path(tmpdir) / "test_report.json")
            self.assertTrue(path.exists())
            data = json.loads(path.read_text())
            self.assertEqual(data["target"], TARGET_HOST)

    def test_print_summary(self):
        """print_summary should not raise."""
        r = ScanReport(
            timestamp="2025-01-01T00:00:00Z",
            target=TARGET_HOST,
            summary="Test summary",
        )
        r.print_summary()  # Should not raise


class TestDNSResolution(unittest.TestCase):
    """Test DNS resolution."""

    @patch("hicloud_scanner.socket.getaddrinfo")
    def test_resolve_host_success(self, mock_gai):
        mock_gai.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("1.2.3.4", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::1", 0, 0, 0)),
        ]
        ips = resolve_host("test.example.com")
        self.assertIn("1.2.3.4", ips)
        self.assertIn("::1", ips)

    @patch("hicloud_scanner.socket.getaddrinfo",
           side_effect=socket.gaierror("DNS failed"))
    def test_resolve_host_failure(self, mock_gai):
        ips = resolve_host("nonexistent.invalid")
        self.assertEqual(ips, [])


class TestScanTcpPort(unittest.TestCase):
    """Test TCP port scanning."""

    @patch("hicloud_scanner.socket.socket")
    def test_open_port(self, mock_sock_class):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK"
        mock_sock_class.return_value = mock_sock

        result = scan_tcp_port("1.2.3.4", 80)
        self.assertEqual(result.state, "open")
        self.assertEqual(result.port, 80)

    @patch("hicloud_scanner.socket.socket")
    def test_closed_port(self, mock_sock_class):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111  # ECONNREFUSED
        mock_sock_class.return_value = mock_sock

        result = scan_tcp_port("1.2.3.4", 12345)
        self.assertEqual(result.state, "closed")

    @patch("hicloud_scanner.socket.socket",
           side_effect=socket.timeout())
    def test_filtered_port(self, mock_sock_class):
        result = scan_tcp_port("1.2.3.4", 445)
        self.assertEqual(result.state, "filtered")

    @patch("hicloud_scanner.socket.socket",
           side_effect=ConnectionResetError())
    def test_rst_port(self, mock_sock_class):
        result = scan_tcp_port("1.2.3.4", 80)
        self.assertEqual(result.state, "rst")


class TestScanUdpPort(unittest.TestCase):
    """Test UDP port probing."""

    @patch("hicloud_scanner.socket.socket")
    def test_open_udp(self, mock_sock_class):
        mock_sock = MagicMock()
        mock_sock.recvfrom.return_value = (b"\x00" * 64, ("1.2.3.4", 53))
        mock_sock_class.return_value = mock_sock

        result = scan_udp_port("1.2.3.4", 53)
        self.assertEqual(result.state, "open")

    @patch("hicloud_scanner.socket.socket")
    def test_filtered_udp(self, mock_sock_class):
        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = socket.timeout()
        mock_sock_class.return_value = mock_sock

        result = scan_udp_port("1.2.3.4", 161)
        self.assertEqual(result.state, "open|filtered")


class TestHttpProbe(unittest.TestCase):
    """Test HTTP probing (mocked)."""

    @patch("hicloud_scanner.requests")
    def test_get_200(self, mock_requests):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "Server": "nginx",
            "Content-Type": "text/html",
            "Content-Length": "1234",
        }
        mock_resp.content = b"Hello"
        mock_resp.text = "Hello"

        mock_session = MagicMock()
        mock_session.get.return_value = mock_resp

        result = http_probe("http://example.com", session=mock_session)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.server, "nginx")

    @patch("hicloud_scanner.requests")
    def test_head_method(self, mock_requests):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Length": "50000000"}
        mock_resp.content = b""
        mock_resp.text = ""

        mock_session = MagicMock()
        mock_session.head.return_value = mock_resp

        result = http_probe("http://example.com/fw.bin", method="HEAD",
                            session=mock_session)
        self.assertEqual(result.method, "HEAD")
        self.assertEqual(result.status_code, 200)

    @patch("hicloud_scanner.requests")
    def test_post_method(self, mock_requests):
        mock_resp = MagicMock()
        mock_resp.status_code = 405
        mock_resp.headers = {}
        mock_resp.content = b""
        mock_resp.text = ""

        mock_session = MagicMock()
        mock_session.post.return_value = mock_resp

        result = http_probe("http://example.com/", method="POST",
                            session=mock_session)
        self.assertEqual(result.method, "POST")

    @patch("hicloud_scanner.requests")
    def test_options_method(self, mock_requests):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Allow": "GET, HEAD, OPTIONS"}
        mock_resp.content = b""
        mock_resp.text = ""

        mock_session = MagicMock()
        mock_session.options.return_value = mock_resp

        result = http_probe("http://example.com/", method="OPTIONS",
                            session=mock_session)
        self.assertEqual(result.method, "OPTIONS")

    def test_connection_error_without_requests(self):
        """If requests is None, should return error."""
        import hicloud_scanner
        orig = hicloud_scanner.requests
        try:
            hicloud_scanner.requests = None
            result = http_probe("http://example.com")
            self.assertIn("not installed", result.error)
        finally:
            hicloud_scanner.requests = orig


class TestProbeUrlMultiMethod(unittest.TestCase):
    """Test multi-method/multi-UA probing."""

    @patch("hicloud_scanner.http_probe")
    def test_generates_all_combinations(self, mock_probe):
        mock_probe.return_value = HttpProbeResult(
            url="http://example.com", method="GET", user_agent="test",
            status_code=200,
        )
        results = probe_url_multi_method(
            "http://example.com",
            user_agents=["UA1", "UA2"],
            methods=["GET", "HEAD"],
        )
        # 2 UAs × 2 methods = 4 probes
        self.assertEqual(len(results), 4)
        self.assertEqual(mock_probe.call_count, 4)


class TestDiscoverPaths(unittest.TestCase):
    """Test path discovery."""

    @patch("hicloud_scanner.http_probe")
    def test_probes_all_paths(self, mock_probe):
        mock_probe.return_value = HttpProbeResult(
            url="http://example.com/test", method="GET", user_agent="test",
            status_code=404,
        )
        paths = ["/a/", "/b/", "/c/"]
        results = discover_paths("http://example.com:8180", paths)
        self.assertEqual(len(results), 3)


class TestDiscoverIndexFiles(unittest.TestCase):
    """Test index file discovery."""

    @patch("hicloud_scanner.http_probe")
    def test_probes_filenames(self, mock_probe):
        mock_probe.return_value = HttpProbeResult(
            url="http://example.com/index.html", method="GET",
            user_agent="test", status_code=404,
        )
        results = discover_index_files(
            "http://example.com/dir/",
            filenames=["index.html", "index.xml"],
        )
        self.assertEqual(len(results), 2)


class TestSearchFirmwareFiles(unittest.TestCase):
    """Test firmware file search."""

    @patch("hicloud_scanner.http_probe")
    def test_checks_all_firmware_files(self, mock_probe):
        mock_probe.return_value = HttpProbeResult(
            url="http://example.com/HG8145V5.bin", method="HEAD",
            user_agent="HuaweiHomeGateway", status_code=404,
        )
        candidates = search_firmware_files(
            "http://example.com",
            firmware_files=["HG8145V5.bin", "HG8145V5-12.bin"],
        )
        self.assertEqual(len(candidates), 2)

    @patch("hicloud_scanner.http_probe")
    def test_identifies_downloadable(self, mock_probe):
        mock_probe.return_value = HttpProbeResult(
            url="http://example.com/HG8145V5.bin", method="HEAD",
            user_agent="HuaweiHomeGateway", status_code=200,
            content_type="application/octet-stream",
            content_length=50_000_000,
        )
        candidates = search_firmware_files(
            "http://example.com",
            firmware_files=["HG8145V5.bin"],
        )
        self.assertEqual(len(candidates), 1)
        self.assertTrue(candidates[0].is_downloadable)

    @patch("hicloud_scanner.http_probe")
    def test_not_downloadable_small_html(self, mock_probe):
        mock_probe.return_value = HttpProbeResult(
            url="http://example.com/HG8145V5.bin", method="HEAD",
            user_agent="HuaweiHomeGateway", status_code=200,
            content_type="text/html",
            content_length=500,
        )
        candidates = search_firmware_files(
            "http://example.com",
            firmware_files=["HG8145V5.bin"],
        )
        self.assertFalse(candidates[0].is_downloadable)


class TestNmapResult(unittest.TestCase):
    """Test NmapResult dataclass."""

    def test_to_dict_empty(self):
        nr = NmapResult(host="1.2.3.4", scan_type="port_scan")
        d = nr.to_dict()
        self.assertEqual(d["host"], "1.2.3.4")
        self.assertEqual(d["scan_type"], "port_scan")

    def test_to_dict_with_ports(self):
        nr = NmapResult(
            host="1.2.3.4", scan_type="port_scan",
            open_ports=["80/tcp", "443/tcp"],
            services=["80/tcp http (nginx 1.18)", "443/tcp https"],
        )
        d = nr.to_dict()
        self.assertEqual(len(d["open_ports"]), 2)
        self.assertEqual(len(d["services"]), 2)

    def test_to_dict_with_vulns(self):
        nr = NmapResult(
            host="1.2.3.4", scan_type="vuln_scan",
            vulnerabilities=["[80/tcp] http-vuln-cve2017-5638: VULNERABLE"],
        )
        d = nr.to_dict()
        self.assertEqual(len(d["vulnerabilities"]), 1)

    def test_to_dict_with_error(self):
        nr = NmapResult(host="1.2.3.4", scan_type="port_scan",
                        error="nmap not installed")
        d = nr.to_dict()
        self.assertIn("error", d)


class TestNmapAvailable(unittest.TestCase):
    """Test nmap availability check."""

    @patch("hicloud_scanner.shutil.which", return_value="/usr/bin/nmap")
    def test_nmap_found(self, mock_which):
        self.assertTrue(_nmap_available())

    @patch("hicloud_scanner.shutil.which", return_value=None)
    def test_nmap_not_found(self, mock_which):
        self.assertFalse(_nmap_available())


class TestParseNmapXml(unittest.TestCase):
    """Test nmap XML output parsing."""

    def test_parse_empty(self):
        result = _parse_nmap_xml("<nmaprun></nmaprun>")
        self.assertEqual(result["ports"], [])
        self.assertEqual(result["services"], [])

    def test_parse_invalid_xml(self):
        result = _parse_nmap_xml("not xml at all")
        self.assertEqual(result["ports"], [])

    def test_parse_open_port(self):
        xml = """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <ports>
              <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="nginx" version="1.18"/>
              </port>
              <port protocol="tcp" portid="443">
                <state state="open"/>
                <service name="https"/>
              </port>
              <port protocol="tcp" portid="22">
                <state state="closed"/>
                <service name="ssh"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""
        result = _parse_nmap_xml(xml)
        self.assertEqual(len(result["ports"]), 2)
        self.assertIn("80/tcp", result["ports"])
        self.assertIn("443/tcp", result["ports"])
        # Closed port should not appear
        self.assertNotIn("22/tcp", result["ports"])

    def test_parse_script_vuln(self):
        xml = """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <ports>
              <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http"/>
                <script id="http-vuln-cve2017-5638"
                        output="VULNERABLE: Apache Struts RCE"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""
        result = _parse_nmap_xml(xml)
        self.assertEqual(len(result["scripts"]), 1)
        self.assertIn("VULNERABLE", result["scripts"][0]["output"])

    def test_parse_os_detection(self):
        xml = """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <os><osmatch name="Linux 4.4" accuracy="95"/></os>
            <ports>
              <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""
        result = _parse_nmap_xml(xml)
        self.assertEqual(result["os"], "Linux 4.4")


class TestRunNmapScan(unittest.TestCase):
    """Test run_nmap_scan function."""

    @patch("hicloud_scanner._nmap_available", return_value=False)
    def test_nmap_not_installed(self, mock_avail):
        nr = run_nmap_scan("1.2.3.4")
        self.assertEqual(nr.error, "nmap not installed")

    @patch("hicloud_scanner._nmap_available", return_value=True)
    @patch("hicloud_scanner.subprocess.run")
    @patch("hicloud_scanner.os.path.exists", return_value=False)
    def test_nmap_timeout(self, mock_exists, mock_run, mock_avail):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="nmap", timeout=300)
        nr = run_nmap_scan("1.2.3.4", timeout=300)
        self.assertIn("timed out", nr.error)

    def test_unknown_scan_type(self):
        nr = run_nmap_scan("1.2.3.4", scan_type="bogus")
        # Either nmap not installed or unknown scan_type
        self.assertTrue(nr.error != "")


class TestDownloadWordlists(unittest.TestCase):
    """Test GitHub wordlist download."""

    def test_wordlist_download_urls_exist(self):
        """GITHUB_WORDLISTS should have download_urls."""
        self.assertIn("download_urls", GITHUB_WORDLISTS)
        self.assertGreater(len(GITHUB_WORDLISTS["download_urls"]), 3)

    def test_wordlist_urls_are_raw_github(self):
        for url in GITHUB_WORDLISTS["download_urls"]:
            self.assertTrue(
                url.startswith("https://raw.githubusercontent.com/"),
                f"URL is not raw GitHub: {url}",
            )

    @patch("hicloud_scanner.requests", None)
    def test_download_without_requests(self):
        downloaded, paths = download_wordlists()
        self.assertEqual(downloaded, [])
        self.assertEqual(paths, [])

    @patch("hicloud_scanner._get_session")
    def test_download_mocked(self, mock_session_fn):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"admin\nbackup\nconfig\nfirmware\nupdate\n"
        mock_resp.text = "admin\nbackup\nconfig\nfirmware\nupdate\n"
        mock_session.get.return_value = mock_resp
        mock_session_fn.return_value = mock_session

        with tempfile.TemporaryDirectory() as tmpdir:
            downloaded, paths = download_wordlists(
                dest_dir=Path(tmpdir), max_lists=2,
            )
            self.assertEqual(len(downloaded), 2)
            self.assertGreater(len(paths), 0)
            self.assertIn("/admin", paths)
            self.assertIn("/firmware", paths)


class TestLoadWordlistPaths(unittest.TestCase):
    """Test loading paths from wordlist files."""

    def test_load_from_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                         delete=False) as f:
            f.write("# comment\nadmin\nbackup\n/config\n\nupdate\n")
            f.flush()
            paths = load_wordlist_paths([f.name])
            self.assertIn("/admin", paths)
            self.assertIn("/backup", paths)
            self.assertIn("/config", paths)
            self.assertIn("/update", paths)
            os.unlink(f.name)

    def test_load_nonexistent_file(self):
        paths = load_wordlist_paths(["/nonexistent/file.txt"])
        self.assertEqual(paths, [])

    def test_deduplication(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                         delete=False) as f:
            f.write("admin\nadmin\nadmin\n")
            f.flush()
            paths = load_wordlist_paths([f.name])
            self.assertEqual(len(paths), 1)
            os.unlink(f.name)


class TestScanReportNewFields(unittest.TestCase):
    """Test new fields in ScanReport."""

    def test_nmap_results_field(self):
        r = ScanReport()
        self.assertEqual(r.nmap_results, [])

    def test_wordlists_downloaded_field(self):
        r = ScanReport()
        self.assertEqual(r.wordlists_downloaded, [])

    def test_to_dict_includes_nmap(self):
        r = ScanReport(
            nmap_results=[NmapResult(host="1.2.3.4", scan_type="port_scan")],
        )
        d = r.to_dict()
        self.assertIn("nmap_results", d)
        self.assertEqual(len(d["nmap_results"]), 1)

    def test_to_dict_includes_wordlists(self):
        r = ScanReport(wordlists_downloaded=["/tmp/common.txt"])
        d = r.to_dict()
        self.assertIn("wordlists_downloaded", d)
        self.assertEqual(d["wordlists_downloaded"], ["/tmp/common.txt"])

    def test_print_summary_with_nmap(self):
        """print_summary with nmap data should not raise."""
        r = ScanReport(
            timestamp="2025-01-01",
            nmap_results=[NmapResult(
                host="1.2.3.4", scan_type="port_scan",
                open_ports=["80/tcp"],
                vulnerabilities=["[80/tcp] test-vuln: VULNERABLE"],
            )],
            wordlists_downloaded=["/tmp/common.txt"],
            summary="Test",
        )
        r.print_summary()  # Should not raise


if __name__ == "__main__":
    unittest.main()
