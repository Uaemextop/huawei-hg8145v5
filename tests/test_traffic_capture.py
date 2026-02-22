"""Tests for the network traffic capture tool.

These tests verify credential extraction, CWMP analysis, port scanning,
ARP packet building, DNS spoofing, and packet dissection without requiring
network access or administrator privileges.
"""

import base64
import socket
import struct
import unittest
from unittest.mock import MagicMock, patch

from tools.traffic_capture import (
    ARP_HW_TYPE_ETHERNET,
    ARP_OP_REPLY,
    ARP_OP_REQUEST,
    BROADCAST_MAC,
    ETH_P_ARP,
    ETH_P_IP,
    IPPROTO_TCP,
    IPPROTO_UDP,
    ARPSpoofer,
    CapturedCredential,
    CapturedPacket,
    CWMPAnalyzer,
    CredentialExtractor,
    DNSSpoofer,
    NetworkScanner,
    PacketCapture,
    ScanResult,
    _ip_bytes,
    _ip_str,
    _mac_bytes,
    _mac_str,
)

# ---------------------------------------------------------------------------
# Sample payloads
# ---------------------------------------------------------------------------

SAMPLE_HTTP_POST = (
    b"POST /login.cgi HTTP/1.1\r\n"
    b"Host: 192.168.100.1\r\n"
    b"Cookie: body:Language:english:id=abc123\r\n"
    b"\r\n"
    b"UserName=Mega_gpon&PassWord=ZWVmOTBiMTQ5NjQzMDcwNw%3D%3D&x.X_HW_Token=deadbeef"
)

SAMPLE_BASIC_AUTH = (
    b"GET /status HTTP/1.1\r\n"
    b"Host: 192.168.100.1\r\n"
    b"Authorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n"
    b"\r\n"
)

SAMPLE_DIGEST_AUTH = (
    b"GET /secure HTTP/1.1\r\n"
    b"Host: 192.168.100.1\r\n"
    b'Authorization: Digest username="admin", realm="router", nonce="abc", response="def"\r\n'
    b"\r\n"
)

SAMPLE_TR069_SOAP = (
    b'<?xml version="1.0"?>\r\n'
    b"<SOAP-ENV:Envelope "
    b'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">\r\n'
    b"<SOAP-ENV:Body>\r\n"
    b"<cwmp:Inform>\r\n"
    b"<Username>tr069user</Username>\r\n"
    b"<Password>tr069pass</Password>\r\n"
    b"</cwmp:Inform>\r\n"
    b"</SOAP-ENV:Body>\r\n"
    b"</SOAP-ENV:Envelope>\r\n"
)

SAMPLE_CWMP_INFORM = (
    b'<?xml version="1.0"?>'
    b'<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    b"<SOAP-ENV:Body>"
    b"<cwmp:Inform>"
    b"<ParameterList>"
    b"<ParameterValueStruct>"
    b"<Name>InternetGatewayDevice.ManagementServer.URL</Name>"
    b"<Value>http://acs.isp.com:7547/acs</Value>"
    b"</ParameterValueStruct>"
    b"<ParameterValueStruct>"
    b"<Name>InternetGatewayDevice.DeviceInfo.SerialNumber</Name>"
    b"<Value>48575443C1234567</Value>"
    b"</ParameterValueStruct>"
    b"<ParameterValueStruct>"
    b"<Name>InternetGatewayDevice.DeviceInfo.SoftwareVersion</Name>"
    b"<Value>V5R020C10S115</Value>"
    b"</ParameterValueStruct>"
    b"</ParameterList>"
    b"</cwmp:Inform>"
    b"</SOAP-ENV:Body>"
    b"</SOAP-ENV:Envelope>"
)

SAMPLE_GPV_RESPONSE_PAYLOAD = (
    b'<?xml version="1.0"?>'
    b'<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    b"<SOAP-ENV:Body>"
    b"<cwmp:GetParameterValuesResponse>"
    b"<ParameterList>"
    b"<ParameterValueStruct>"
    b"<Name>InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID</Name>"
    b"<Value>TestWiFi</Value>"
    b"</ParameterValueStruct>"
    b"</ParameterList>"
    b"</cwmp:GetParameterValuesResponse>"
    b"</SOAP-ENV:Body>"
    b"</SOAP-ENV:Envelope>"
)


def _make_packet(payload: bytes, src_ip: str = "192.168.100.50",
                 dst_ip: str = "192.168.100.1",
                 src_port: int = 12345, dst_port: int = 80) -> CapturedPacket:
    """Create a CapturedPacket for testing."""
    return CapturedPacket(
        timestamp="20250101T000000Z",
        src_mac="aa:bb:cc:dd:ee:ff",
        dst_mac="11:22:33:44:55:66",
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol="TCP",
        src_port=src_port,
        dst_port=dst_port,
        payload=payload,
    )


# ===================================================================
# CredentialExtractor tests
# ===================================================================

class TestCredentialExtractor(unittest.TestCase):
    """Test credential extraction from captured packets."""

    def setUp(self):
        self.extractor = CredentialExtractor()

    def test_http_login_username(self):
        pkt = _make_packet(SAMPLE_HTTP_POST)
        creds = self.extractor.extract(pkt)
        login_creds = [c for c in creds if c.cred_type == "http-login"]
        self.assertTrue(len(login_creds) >= 1)
        self.assertEqual(login_creds[0].username, "Mega_gpon")

    def test_http_login_password_base64_decode(self):
        pkt = _make_packet(SAMPLE_HTTP_POST)
        creds = self.extractor.extract(pkt)
        login_creds = [c for c in creds if c.cred_type == "http-login"]
        self.assertTrue(len(login_creds) >= 1)
        # The raw password is URL-decoded base64: ZWVmOTBiMTQ5NjQzMDcwNw==
        # which decodes to "eef90b1496430707"
        self.assertEqual(login_creds[0].password, "eef90b1496430707")
        self.assertIn("ZWVmOTBiMTQ5NjQzMDcwNw==", login_creds[0].password_raw)

    def test_cookie_extraction(self):
        # Cookie regex requires another header (or EOF) after the cookie line
        payload = (
            b"GET / HTTP/1.1\r\n"
            b"Host: 192.168.100.1\r\n"
            b"Cookie: body:Language:english:id=abc123\r\n"
            b"Accept: */*\r\n"
            b"\r\n"
        )
        pkt = _make_packet(payload)
        creds = self.extractor.extract(pkt)
        cookie_creds = [c for c in creds if c.cred_type == "cookie"]
        self.assertTrue(len(cookie_creds) >= 1)
        self.assertIn("body:Language:english", cookie_creds[0].extra["cookie"])

    def test_hw_token_extraction(self):
        pkt = _make_packet(SAMPLE_HTTP_POST)
        creds = self.extractor.extract(pkt)
        token_creds = [c for c in creds if c.cred_type == "hw-token"]
        self.assertTrue(len(token_creds) >= 1)
        self.assertEqual(token_creds[0].extra["token"], "deadbeef")

    def test_basic_auth_extraction(self):
        pkt = _make_packet(SAMPLE_BASIC_AUTH)
        creds = self.extractor.extract(pkt)
        basic_creds = [c for c in creds if c.cred_type == "basic-auth"]
        self.assertTrue(len(basic_creds) >= 1)
        self.assertEqual(basic_creds[0].username, "admin")
        self.assertEqual(basic_creds[0].password, "password")

    def test_digest_auth_extraction(self):
        pkt = _make_packet(SAMPLE_DIGEST_AUTH)
        creds = self.extractor.extract(pkt)
        digest_creds = [c for c in creds if c.cred_type == "digest-auth"]
        self.assertTrue(len(digest_creds) >= 1)
        self.assertIn("username=", digest_creds[0].extra["raw"])

    def test_tr069_soap_credential_extraction(self):
        pkt = _make_packet(SAMPLE_TR069_SOAP, dst_port=7547)
        creds = self.extractor.extract(pkt)
        acs_creds = [c for c in creds if c.cred_type == "tr069-acs"]
        self.assertTrue(len(acs_creds) >= 1)
        self.assertEqual(acs_creds[0].username, "tr069user")
        self.assertEqual(acs_creds[0].password, "tr069pass")

    def test_no_credentials_in_plain_text(self):
        pkt = _make_packet(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        creds = self.extractor.extract(pkt)
        self.assertEqual(len(creds), 0)

    def test_credentials_stored_internally(self):
        pkt = _make_packet(SAMPLE_BASIC_AUTH)
        self.extractor.extract(pkt)
        self.assertGreater(len(self.extractor.credentials), 0)


# ===================================================================
# CWMPAnalyzer tests
# ===================================================================

class TestCWMPAnalyzer(unittest.TestCase):
    """Test CWMP/TR-069 SOAP traffic analysis."""

    def setUp(self):
        self.analyzer = CWMPAnalyzer()

    def test_acs_url_extraction(self):
        pkt = _make_packet(SAMPLE_CWMP_INFORM, dst_port=7547)
        result = self.analyzer.analyse(pkt)
        self.assertEqual(result.get("acs_url"), "http://acs.isp.com:7547/acs")
        self.assertEqual(self.analyzer.acs_url, "http://acs.isp.com:7547/acs")

    def test_serial_extraction(self):
        pkt = _make_packet(SAMPLE_CWMP_INFORM, dst_port=7547)
        result = self.analyzer.analyse(pkt)
        self.assertEqual(result.get("serial"), "48575443C1234567")

    def test_firmware_extraction(self):
        pkt = _make_packet(SAMPLE_CWMP_INFORM, dst_port=7547)
        result = self.analyzer.analyse(pkt)
        self.assertEqual(result.get("firmware"), "V5R020C10S115")

    def test_inform_detected(self):
        pkt = _make_packet(SAMPLE_CWMP_INFORM, dst_port=7547)
        result = self.analyzer.analyse(pkt)
        self.assertEqual(result.get("message_type"), "Inform")

    def test_gpv_response_parameters(self):
        pkt = _make_packet(SAMPLE_GPV_RESPONSE_PAYLOAD, dst_port=7547)
        result = self.analyzer.analyse(pkt)
        self.assertEqual(result.get("message_type"), "GetParameterValuesResponse")
        params = result.get("parameters", {})
        self.assertEqual(
            params.get(
                "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID"
            ),
            "TestWiFi",
        )

    def test_non_soap_ignored(self):
        pkt = _make_packet(b"just plain text, no XML here")
        result = self.analyzer.analyse(pkt)
        self.assertEqual(result, {})

    def test_summary(self):
        pkt = _make_packet(SAMPLE_CWMP_INFORM, dst_port=7547)
        self.analyzer.analyse(pkt)
        summary = self.analyzer.summary()
        self.assertEqual(summary["acs_url"], "http://acs.isp.com:7547/acs")
        self.assertIsInstance(summary["parameter_count"], int)


# ===================================================================
# NetworkScanner tests
# ===================================================================

class TestNetworkScanner(unittest.TestCase):
    """Test port scanning with mocked sockets."""

    @patch("tools.traffic_capture.socket.socket")
    def test_port_open(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.connect.return_value = None
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\n"

        scanner = NetworkScanner("192.168.100.1", ports={80: "HTTP"}, timeout=1.0)
        results = scanner.scan()

        open_results = [r for r in results if r.state == "open"]
        self.assertEqual(len(open_results), 1)
        self.assertEqual(open_results[0].port, 80)
        self.assertEqual(open_results[0].service, "HTTP")

    @patch("tools.traffic_capture.socket.socket")
    def test_port_closed(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.connect.side_effect = ConnectionRefusedError()

        scanner = NetworkScanner("192.168.100.1", ports={23: "Telnet"}, timeout=1.0)
        results = scanner.scan()

        closed = [r for r in results if r.state == "closed"]
        self.assertEqual(len(closed), 1)
        self.assertEqual(closed[0].port, 23)

    @patch("tools.traffic_capture.socket.socket")
    def test_port_timeout_filtered(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.connect.side_effect = socket.timeout()

        scanner = NetworkScanner("192.168.100.1", ports={7547: "TR-069"}, timeout=1.0)
        results = scanner.scan()

        filtered = [r for r in results if r.state == "filtered"]
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].port, 7547)

    def test_scan_result_dataclass(self):
        r = ScanResult(port=80, service="HTTP", state="open", banner="nginx")
        d = r.as_dict()
        self.assertEqual(d["port"], 80)
        self.assertEqual(d["state"], "open")
        self.assertEqual(d["banner"], "nginx")


# ===================================================================
# ARPSpoofer tests
# ===================================================================

class TestARPSpoofer(unittest.TestCase):
    """Test ARP packet building."""

    def test_build_arp_reply_length(self):
        src_mac = _mac_bytes("aa:bb:cc:dd:ee:ff")
        dst_mac = _mac_bytes("11:22:33:44:55:66")
        src_ip = _ip_bytes("192.168.100.50")
        dst_ip = _ip_bytes("192.168.100.1")

        packet = ARPSpoofer.build_arp_packet(src_mac, dst_mac, src_ip, dst_ip)
        # Ethernet header (14) + ARP payload (28) = 42 bytes
        self.assertEqual(len(packet), 42)

    def test_build_arp_reply_ethertype(self):
        src_mac = _mac_bytes("aa:bb:cc:dd:ee:ff")
        dst_mac = _mac_bytes("11:22:33:44:55:66")
        src_ip = _ip_bytes("192.168.100.50")
        dst_ip = _ip_bytes("192.168.100.1")

        packet = ARPSpoofer.build_arp_packet(src_mac, dst_mac, src_ip, dst_ip)
        eth_type = struct.unpack("!H", packet[12:14])[0]
        self.assertEqual(eth_type, ETH_P_ARP)

    def test_build_arp_reply_opcode(self):
        src_mac = _mac_bytes("aa:bb:cc:dd:ee:ff")
        dst_mac = _mac_bytes("11:22:33:44:55:66")
        src_ip = _ip_bytes("192.168.100.50")
        dst_ip = _ip_bytes("192.168.100.1")

        packet = ARPSpoofer.build_arp_packet(
            src_mac, dst_mac, src_ip, dst_ip, opcode=ARP_OP_REPLY
        )
        opcode = struct.unpack("!H", packet[20:22])[0]
        self.assertEqual(opcode, ARP_OP_REPLY)

    def test_build_arp_request_broadcast(self):
        src_mac = _mac_bytes("aa:bb:cc:dd:ee:ff")
        src_ip = _ip_bytes("192.168.100.50")
        target_ip = _ip_bytes("192.168.100.1")

        packet = ARPSpoofer.build_arp_request(src_mac, src_ip, target_ip)
        # Destination MAC should be broadcast
        dst = packet[0:6]
        self.assertEqual(dst, BROADCAST_MAC)
        # Opcode should be REQUEST
        opcode = struct.unpack("!H", packet[20:22])[0]
        self.assertEqual(opcode, ARP_OP_REQUEST)

    def test_build_arp_packet_sender_ip(self):
        src_mac = _mac_bytes("aa:bb:cc:dd:ee:ff")
        dst_mac = _mac_bytes("11:22:33:44:55:66")
        src_ip = _ip_bytes("192.168.100.50")
        dst_ip = _ip_bytes("192.168.100.1")

        packet = ARPSpoofer.build_arp_packet(src_mac, dst_mac, src_ip, dst_ip)
        sender_ip = packet[28:32]
        self.assertEqual(sender_ip, src_ip)
        target_ip_extracted = packet[38:42]
        self.assertEqual(target_ip_extracted, dst_ip)


# ===================================================================
# DNSSpoofer tests
# ===================================================================

class TestDNSSpoofer(unittest.TestCase):
    """Test DNS response building and domain matching."""

    def _build_dns_query(self, domain: str, txn_id: bytes = b"\x12\x34") -> bytes:
        """Build a minimal DNS query for testing."""
        # Header: txn_id(2) + flags(2) + QD(2) + AN(2) + NS(2) + AR(2)
        header = txn_id + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0)
        # Question section
        question = b""
        for label in domain.split("."):
            question += bytes([len(label)]) + label.encode("ascii")
        question += b"\x00"  # root label
        question += struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN
        return header + question

    def test_spoof_response_for_target_domain(self):
        spoofer = DNSSpoofer(
            target_domain="acs.isp.com",
            redirect_ip="192.168.100.50",
        )
        query = self._build_dns_query("acs.isp.com")
        response = spoofer._handle_query(query)
        self.assertIsNotNone(response)

        # Verify it's a response (bit 15 set)
        flags = struct.unpack("!H", response[2:4])[0]
        self.assertTrue(flags & 0x8000)

        # Verify answer contains our redirect IP
        redirect_bytes = _ip_bytes("192.168.100.50")
        self.assertIn(redirect_bytes, response)

    def test_non_matching_domain_forwarded(self):
        spoofer = DNSSpoofer(
            target_domain="acs.isp.com",
            redirect_ip="192.168.100.50",
        )
        query = self._build_dns_query("www.google.com")
        # Mock the _forward_query to avoid real DNS
        with patch.object(spoofer, "_forward_query", return_value=b"\x00" * 12) as mock_fwd:
            response = spoofer._handle_query(query)
            mock_fwd.assert_called_once()

    def test_build_spoof_response_structure(self):
        spoofer = DNSSpoofer(
            target_domain="acs.isp.com",
            redirect_ip="10.0.0.1",
        )
        txn_id = b"\xAB\xCD"
        question_section = b"\x03acs\x03isp\x03com\x00\x00\x01\x00\x01"
        response = spoofer._build_spoof_response(
            txn_id, question_section, "acs.isp.com", 1, 1
        )
        # Check transaction ID preserved
        self.assertEqual(response[0:2], txn_id)
        # Check AN count = 1
        an_count = struct.unpack("!H", response[6:8])[0]
        self.assertEqual(an_count, 1)
        # Check redirect IP is in the response
        self.assertIn(_ip_bytes("10.0.0.1"), response)

    def test_ignore_dns_response_packets(self):
        spoofer = DNSSpoofer(
            target_domain="acs.isp.com",
            redirect_ip="192.168.100.50",
        )
        # Set bit 15 (QR=1, meaning this is a response, not a query)
        response_pkt = b"\x12\x34" + struct.pack("!H", 0x8180) + b"\x00" * 8
        result = spoofer._handle_query(response_pkt)
        self.assertIsNone(result)

    def test_read_qname(self):
        # Encode "acs.isp.com"
        raw = b"\x03acs\x03isp\x03com\x00"
        name, offset = DNSSpoofer._read_qname(raw, 0)
        self.assertEqual(name, "acs.isp.com")
        self.assertEqual(offset, len(raw))


# ===================================================================
# PacketCapture tests (dissection)
# ===================================================================

class TestPacketCapture(unittest.TestCase):
    """Test packet dissection of Ethernet, IP, TCP, UDP headers."""

    def setUp(self):
        self.capture = PacketCapture(
            our_ip="192.168.100.50",
            router_ip="192.168.100.1",
        )

    def _build_ip_tcp_packet(
        self,
        src_ip: str = "192.168.100.1",
        dst_ip: str = "192.168.100.50",
        src_port: int = 80,
        dst_port: int = 12345,
        payload: bytes = b"HTTP/1.1 200 OK\r\n",
    ) -> bytes:
        """Build a minimal IP+TCP packet (no Ethernet header)."""
        tcp_data_offset = 5  # 20 bytes, no options
        tcp_header = struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            0,  # seq
            0,  # ack
            (tcp_data_offset << 4),  # data offset
            0x18,  # flags (PSH+ACK)
            65535,  # window
            0,  # checksum
            0,  # urgent
        )
        ip_total_len = 20 + len(tcp_header) + len(payload)
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,  # version=4, IHL=5
            0,  # DSCP
            ip_total_len,
            0,  # identification
            0,  # flags+fragment
            64,  # TTL
            IPPROTO_TCP,
            0,  # checksum
            _ip_bytes(src_ip),
            _ip_bytes(dst_ip),
        )
        return ip_header + tcp_header + payload

    def _build_ip_udp_packet(
        self,
        src_ip: str = "192.168.100.1",
        dst_ip: str = "192.168.100.50",
        src_port: int = 53,
        dst_port: int = 12345,
        payload: bytes = b"\x00" * 12,
    ) -> bytes:
        """Build a minimal IP+UDP packet (no Ethernet header)."""
        udp_len = 8 + len(payload)
        udp_header = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
        ip_total_len = 20 + len(udp_header) + len(payload)
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            ip_total_len,
            0,
            0,
            64,
            IPPROTO_UDP,
            0,
            _ip_bytes(src_ip),
            _ip_bytes(dst_ip),
        )
        return ip_header + udp_header + payload

    def _build_ethernet_frame(self, ip_packet: bytes) -> bytes:
        """Wrap an IP packet in an Ethernet frame."""
        dst_mac = _mac_bytes("11:22:33:44:55:66")
        src_mac = _mac_bytes("aa:bb:cc:dd:ee:ff")
        return dst_mac + src_mac + struct.pack("!H", ETH_P_IP) + ip_packet

    def test_parse_ip_packet_tcp(self):
        raw = self._build_ip_tcp_packet()
        pkt = self.capture._parse_ip_packet(raw, "20250101T000000Z")
        self.assertIsNotNone(pkt)
        self.assertEqual(pkt.src_ip, "192.168.100.1")
        self.assertEqual(pkt.dst_ip, "192.168.100.50")
        self.assertEqual(pkt.protocol, "TCP")
        self.assertEqual(pkt.src_port, 80)
        self.assertEqual(pkt.dst_port, 12345)
        self.assertIn(b"HTTP/1.1 200 OK", pkt.payload)

    def test_parse_ip_packet_udp(self):
        raw = self._build_ip_udp_packet()
        pkt = self.capture._parse_ip_packet(raw, "20250101T000000Z")
        self.assertIsNotNone(pkt)
        self.assertEqual(pkt.protocol, "UDP")
        self.assertEqual(pkt.src_port, 53)

    def test_parse_ethernet_frame(self):
        ip_pkt = self._build_ip_tcp_packet()
        frame = self._build_ethernet_frame(ip_pkt)
        pkt = self.capture._parse_ethernet_frame(frame, "20250101T000000Z")
        self.assertIsNotNone(pkt)
        self.assertEqual(pkt.src_mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(pkt.dst_mac, "11:22:33:44:55:66")
        self.assertEqual(pkt.protocol, "TCP")

    def test_parse_ethernet_frame_too_short(self):
        pkt = self.capture._parse_ethernet_frame(b"\x00" * 5, "ts")
        self.assertIsNone(pkt)

    def test_parse_ip_packet_too_short(self):
        pkt = self.capture._parse_ip_packet(b"\x00" * 10, "ts")
        self.assertIsNone(pkt)

    def test_parse_non_ip_ethernet_frame(self):
        # Use ARP ethertype instead of IP
        frame = _mac_bytes("11:22:33:44:55:66") + _mac_bytes("aa:bb:cc:dd:ee:ff")
        frame += struct.pack("!H", ETH_P_ARP) + b"\x00" * 28
        pkt = self.capture._parse_ethernet_frame(frame, "ts")
        self.assertIsNone(pkt)

    def test_is_interesting_router_traffic(self):
        pkt = CapturedPacket(
            timestamp="ts", src_mac="", dst_mac="",
            src_ip="192.168.100.1", dst_ip="192.168.100.50",
            protocol="TCP", src_port=80, dst_port=12345,
        )
        self.assertTrue(self.capture._is_interesting(pkt))

    def test_is_not_interesting_unrelated_traffic(self):
        pkt = CapturedPacket(
            timestamp="ts", src_mac="", dst_mac="",
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            protocol="TCP", src_port=9999, dst_port=9998,
        )
        self.assertFalse(self.capture._is_interesting(pkt))


# ===================================================================
# Helper function tests
# ===================================================================

class TestHelpers(unittest.TestCase):
    """Test MAC/IP conversion helpers."""

    def test_mac_bytes_roundtrip(self):
        mac = "aa:bb:cc:dd:ee:ff"
        self.assertEqual(_mac_str(_mac_bytes(mac)), mac)

    def test_ip_bytes_roundtrip(self):
        ip = "192.168.100.1"
        self.assertEqual(_ip_str(_ip_bytes(ip)), ip)

    def test_captured_packet_as_dict(self):
        pkt = CapturedPacket(
            timestamp="ts", src_mac="aa:bb:cc:dd:ee:ff",
            dst_mac="11:22:33:44:55:66", payload=b"hello",
        )
        d = pkt.as_dict()
        self.assertEqual(d["src_mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(d["payload_b64"], base64.b64encode(b"hello").decode())

    def test_captured_credential_as_dict(self):
        cred = CapturedCredential(
            timestamp="ts", source_ip="1.2.3.4", dest_ip="5.6.7.8",
            cred_type="http-login", username="admin", password="pass",
        )
        d = cred.as_dict()
        self.assertEqual(d["type"], "http-login")
        self.assertEqual(d["username"], "admin")


if __name__ == "__main__":
    unittest.main()
