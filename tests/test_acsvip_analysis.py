"""
Tests for acsvip_analysis.py — acsvip.megared.net.mx deep analysis.

All network calls are mocked so tests run offline.
"""

import json
import socket
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acsvip_analysis import (
    TARGET_HOST,
    DEFAULT_TCP_PORTS,
    DEFAULT_UDP_PORTS,
    FIRMWARE_PATHS,
    FIRMWARE_BIN_FILES,
    _USER_AGENTS,
    PortResult,
    HttpProbeResult,
    AnalysisReport,
    resolve_host,
    scan_tcp_port,
    probe_udp_port,
    analyze_tcp_handshake,
)


class TestPortResult(unittest.TestCase):
    """Test PortResult dataclass."""

    def test_to_dict(self):
        r = PortResult(80, "tcp", "open", banner="nginx", latency_ms=12.3)
        d = r.to_dict()
        self.assertEqual(d["port"], 80)
        self.assertEqual(d["protocol"], "tcp")
        self.assertEqual(d["state"], "open")
        self.assertEqual(d["banner"], "nginx")
        self.assertEqual(d["latency_ms"], 12.3)

    def test_rst_result(self):
        r = PortResult(80, "tcp", "rst", banner="RST after handshake")
        self.assertEqual(r.state, "rst")


class TestHttpProbeResult(unittest.TestCase):
    """Test HttpProbeResult dataclass."""

    def test_to_dict_minimal(self):
        r = HttpProbeResult(
            url="http://acsvip.megared.net.mx/",
            method="GET", user_agent="test/1.0",
        )
        d = r.to_dict()
        self.assertEqual(d["url"], "http://acsvip.megared.net.mx/")
        self.assertEqual(d["method"], "GET")
        self.assertNotIn("server", d)  # empty fields omitted

    def test_to_dict_with_error(self):
        r = HttpProbeResult(
            url="http://test/", method="GET",
            user_agent="ua", error="Connection reset",
        )
        d = r.to_dict()
        self.assertIn("error", d)


class TestAnalysisReport(unittest.TestCase):
    """Test AnalysisReport dataclass."""

    def test_to_dict(self):
        report = AnalysisReport()
        report.ipv4 = "201.159.200.30"
        report.tcp_ports = [
            PortResult(80, "tcp", "rst"),
            PortResult(443, "tcp", "filtered"),
        ]
        d = report.to_dict()
        self.assertEqual(d["dns"]["ipv4"], "201.159.200.30")
        self.assertEqual(len(d["tcp_ports"]), 2)
        self.assertEqual(d["rst_tcp"], [80])
        self.assertEqual(d["open_tcp"], [])

    def test_save(self):
        import tempfile
        report = AnalysisReport()
        report.ipv4 = "201.159.200.30"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = report.save(Path(tmpdir) / "report.json")
            self.assertTrue(path.exists())
            data = json.loads(path.read_text())
            self.assertEqual(data["dns"]["ipv4"], "201.159.200.30")


class TestResolveHost(unittest.TestCase):
    """Test DNS resolution."""

    @patch("acsvip_analysis.socket.getaddrinfo")
    @patch("acsvip_analysis.socket.gethostbyaddr")
    def test_resolves_ipv4(self, mock_rdns, mock_dns):
        mock_dns.return_value = [
            (socket.AF_INET, 1, 6, "", ("201.159.200.30", 0)),
        ]
        mock_rdns.return_value = ("customer.megared.net.mx", [], [])
        ipv4, ipv6, rdns = resolve_host("acsvip.megared.net.mx")
        self.assertEqual(ipv4, "201.159.200.30")
        self.assertEqual(rdns, "customer.megared.net.mx")

    @patch("acsvip_analysis.socket.getaddrinfo",
           side_effect=socket.gaierror("not found"))
    def test_no_resolution(self, mock_dns):
        ipv4, ipv6, rdns = resolve_host("nonexistent.test")
        self.assertEqual(ipv4, "")
        self.assertEqual(ipv6, "")


class TestScanTcpPort(unittest.TestCase):
    """Test TCP port scanning."""

    @patch("acsvip_analysis.socket.socket")
    def test_open_port(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.return_value = b"HTTP/1.0 200 OK\r\n"

        r = scan_tcp_port("1.2.3.4", 80)
        self.assertEqual(r.state, "open")
        self.assertIn("HTTP", r.banner)

    @patch("acsvip_analysis.socket.socket")
    def test_rst_port(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.side_effect = ConnectionResetError("reset")

        r = scan_tcp_port("1.2.3.4", 80)
        self.assertEqual(r.state, "rst")
        self.assertIn("RST", r.banner)

    @patch("acsvip_analysis.socket.socket")
    def test_closed_port(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.connect_ex.return_value = 111  # ECONNREFUSED

        r = scan_tcp_port("1.2.3.4", 12345)
        self.assertEqual(r.state, "closed")

    @patch("acsvip_analysis.socket.socket")
    def test_filtered_port(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.connect_ex.side_effect = socket.timeout("timeout")

        r = scan_tcp_port("1.2.3.4", 443)
        self.assertEqual(r.state, "filtered")


class TestProbeUdpPort(unittest.TestCase):
    """Test UDP port probing."""

    @patch("acsvip_analysis.socket.socket")
    def test_open_udp(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recvfrom.return_value = (b"\x00" * 32, ("1.2.3.4", 53))

        r = probe_udp_port("1.2.3.4", 53)
        self.assertEqual(r.state, "open")

    @patch("acsvip_analysis.socket.socket")
    def test_filtered_udp(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recvfrom.side_effect = socket.timeout("timeout")

        r = probe_udp_port("1.2.3.4", 161)
        self.assertEqual(r.state, "open|filtered")


class TestAnalyzeTcpHandshake(unittest.TestCase):
    """Test TCP handshake analysis."""

    @patch("acsvip_analysis.socket.socket")
    def test_immediate_rst_pattern(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recv.side_effect = ConnectionResetError("rst")

        result = analyze_tcp_handshake("1.2.3.4", 80, attempts=2)
        self.assertEqual(result["pattern"], "immediate_rst_after_handshake")
        self.assertIn("interpretation", result)
        self.assertEqual(len(result["attempts"]), 2)


class TestConstants(unittest.TestCase):
    """Test configuration constants."""

    def test_target_host(self):
        self.assertEqual(TARGET_HOST, "acsvip.megared.net.mx")

    def test_tcp_ports_include_tr069(self):
        self.assertIn(7547, DEFAULT_TCP_PORTS)

    def test_tcp_ports_include_http(self):
        self.assertIn(80, DEFAULT_TCP_PORTS)
        self.assertIn(443, DEFAULT_TCP_PORTS)

    def test_udp_ports_include_dns(self):
        self.assertIn(53, DEFAULT_UDP_PORTS)

    def test_firmware_paths_include_firmware(self):
        self.assertIn("/firmware/", FIRMWARE_PATHS)

    def test_firmware_bins_include_hg8145v5(self):
        hg = [f for f in FIRMWARE_BIN_FILES if "HG8145V5" in f]
        self.assertGreater(len(hg), 0)

    def test_user_agents_include_cwmp(self):
        huawei = [ua for ua in _USER_AGENTS if "Huawei" in ua or "HW" in ua]
        self.assertGreater(len(huawei), 0)


if __name__ == "__main__":
    unittest.main()
