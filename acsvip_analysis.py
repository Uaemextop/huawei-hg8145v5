#!/usr/bin/env python3
"""
acsvip.megared.net.mx — Deep Analysis & Port Scanner
=====================================================
Performs DNS resolution, TCP/UDP port scanning, HTTP probing (with
multiple strategies to bypass connection resets), and reports results
for the MEGACABLE TR-069/CWMP ACS server.

Usage
-----
    python acsvip_analysis.py
    python acsvip_analysis.py --tcp-range 1-1024
    python acsvip_analysis.py --udp
    python acsvip_analysis.py --json results.json

The ACS at ``acsvip.megared.net.mx`` (``201.159.200.30``) manages
Huawei HG8145V5 ONT devices and serves firmware ``.bin`` files over
TR-069.  It whitelists connections by source IP (MEGACABLE subscriber
ranges only), so external probes receive immediate TCP RST after the
three-way handshake completes.
"""

import argparse
import json
import socket
import ssl
import struct
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------
TARGET_HOST = "acsvip.megared.net.mx"

# Well-known TCP ports to scan
DEFAULT_TCP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
    1080, 1433, 1723, 2049, 3306, 3389, 4443, 5060, 5061, 5222, 5432,
    6443, 7443, 7547, 7548, 7549, 8000, 8008, 8080, 8081, 8443, 8888,
    8880, 9090, 9443, 10000, 10443, 30005, 37215, 60080,
]

# Well-known UDP ports to probe
DEFAULT_UDP_PORTS = [
    53, 67, 68, 69, 123, 161, 162, 500, 514, 520, 1194, 1701,
    1812, 1813, 4500, 5060, 5353, 7547, 8080, 10161, 33434,
]

# Common firmware file paths to probe on the ACS
FIRMWARE_PATHS = [
    "/firmware/",
    "/firmware/update/",
    "/firmware/download/",
    "/fw/",
    "/update/",
    "/upgrade/",
    "/download/",
    "/bin/",
    "/files/",
    "/acs/",
    "/service/cwmp",
    "/service/",
    "/",
]

# Firmware .bin file names observed for Huawei ONTs deployed by MEGACABLE
FIRMWARE_BIN_FILES = [
    "HG8145V5_V500R022C00SPC368.bin",
    "HG8145V5_V500R020C10SPC212.bin",
    "HG8145V5_V500R020C00SPC458B001.bin",
    "HG8145V5_V500R022C00SPC340B019.bin",
    "EG8145V5-V500R022C00SPC340B019.bin",
    "HG8245C_V500R019C00SPC105.bin",
    "HG8245H_V300R018C10SPC120.bin",
    "HG8245H5_V500R021C00SPC100.bin",
    "HG8546M_V500R020C10SPC200.bin",
    "HG8245Q2_V300R019C00.bin",
    "5611_HG8145V5V500R020C10SPC212.bin",
    "EG8145V5.bin",
    "HG8145V5.bin",
    "firmware.bin",
    "upgrade.bin",
]

# UA strings to try (extracted from EG8145V5 firmware rootfs)
_USER_AGENTS = [
    # Main CWMP session UA (libhw_smp_cwmp_core.so, used by all TR-069 sessions)
    "HuaweiHomeGateway",
    # Bulk data upload UA (libhw_cwmp_bulkchina.so)
    "HW-FTTH",
    # IP/MAC report UA (libhw_cwmp_china_pdt.so)
    "HW_IPMAC_REPORT",
    # HTTP client web market UA (libhw_smp_httpclient.so)
    (
        "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; "
        "Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; "
        ".NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0E; .NET4.0C)"
    ),
    # Web market client UA (libhw_smp_base.so)
    (
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; "
        "Trident/5.0; 2345Explorer)"
    ),
    # Standard browser fallback
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "curl/8.4.0",
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PortResult:
    """Result of a single port probe."""
    port: int
    protocol: str        # "tcp" or "udp"
    state: str           # "open", "closed", "filtered", "open|filtered", "rst"
    banner: str = ""
    latency_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "banner": self.banner,
            "latency_ms": round(self.latency_ms, 1),
        }


@dataclass
class HttpProbeResult:
    """Result of an HTTP probe attempt."""
    url: str
    method: str
    user_agent: str
    status_code: int = 0
    server: str = ""
    content_type: str = ""
    content_length: int = 0
    body_preview: str = ""
    error: str = ""
    redirect: str = ""

    def to_dict(self) -> dict:
        d = {
            "url": self.url,
            "method": self.method,
            "user_agent": self.user_agent[:40],
            "status_code": self.status_code,
        }
        if self.server:
            d["server"] = self.server
        if self.content_type:
            d["content_type"] = self.content_type
        if self.content_length:
            d["content_length"] = self.content_length
        if self.body_preview:
            d["body_preview"] = self.body_preview
        if self.error:
            d["error"] = self.error
        if self.redirect:
            d["redirect"] = self.redirect
        return d


@dataclass
class AnalysisReport:
    """Full analysis report for acsvip.megared.net.mx."""
    timestamp: str = ""
    target: str = TARGET_HOST
    ipv4: str = ""
    ipv6: str = ""
    reverse_dns: str = ""
    tcp_ports: list = field(default_factory=list)
    udp_ports: list = field(default_factory=list)
    http_probes: list = field(default_factory=list)
    firmware_probes: list = field(default_factory=list)
    tcp_handshake: dict = field(default_factory=dict)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "target": self.target,
            "dns": {
                "ipv4": self.ipv4,
                "ipv6": self.ipv6,
                "reverse_dns": self.reverse_dns,
            },
            "tcp_ports": [p.to_dict() for p in self.tcp_ports],
            "udp_ports": [p.to_dict() for p in self.udp_ports],
            "tcp_handshake": self.tcp_handshake,
            "http_probes": [p.to_dict() for p in self.http_probes],
            "firmware_probes": [p.to_dict() for p in self.firmware_probes],
            "summary": self.summary,
            "open_tcp": [p.port for p in self.tcp_ports if p.state == "open"],
            "open_udp": [p.port for p in self.udp_ports if p.state == "open"],
            "rst_tcp": [p.port for p in self.tcp_ports if p.state == "rst"],
        }

    def save(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return path


# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------

def resolve_host(host: str) -> tuple[str, str, str]:
    """Resolve hostname to IPv4, IPv6, and reverse DNS."""
    ipv4 = ""
    ipv6 = ""
    rdns = ""

    try:
        results = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for fam, _typ, _proto, _canon, addr in results:
            ip = addr[0]
            if fam == socket.AF_INET and not ipv4:
                ipv4 = ip
            elif fam == socket.AF_INET6 and not ipv6:
                ipv6 = ip
    except socket.gaierror:
        pass

    if ipv4:
        try:
            rdns = socket.gethostbyaddr(ipv4)[0]
        except (socket.herror, socket.gaierror, OSError):
            pass

    return ipv4, ipv6, rdns


# ---------------------------------------------------------------------------
# TCP port scan
# ---------------------------------------------------------------------------

def scan_tcp_port(host: str, port: int, timeout: float = 3.0) -> PortResult:
    """Scan a single TCP port. Detects open, closed, RST, and filtered."""
    t0 = time.monotonic()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result_code = s.connect_ex((host, port))
        elapsed = (time.monotonic() - t0) * 1000

        if result_code != 0:
            s.close()
            return PortResult(port, "tcp", "closed", latency_ms=elapsed)

        # Connection established — check if server sends RST immediately
        banner = ""
        try:
            s.settimeout(1.5)
            data = s.recv(256)
            if data:
                banner = data.decode("utf-8", errors="replace").strip()[:80]
                s.close()
                return PortResult(port, "tcp", "open", banner=banner,
                                  latency_ms=elapsed)
        except ConnectionResetError:
            s.close()
            return PortResult(port, "tcp", "rst",
                              banner="RST after handshake (IP-whitelisted)",
                              latency_ms=elapsed)
        except socket.timeout:
            pass

        # Server didn't send data or RST — try sending a probe
        try:
            s.settimeout(2)
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            data = s.recv(1024)
            banner = data.decode("utf-8", errors="replace").split("\n")[0][:80]
            s.close()
            return PortResult(port, "tcp", "open", banner=banner,
                              latency_ms=elapsed)
        except ConnectionResetError:
            s.close()
            return PortResult(port, "tcp", "rst",
                              banner="RST on send (IP-whitelisted)",
                              latency_ms=elapsed)
        except (socket.timeout, OSError):
            s.close()
            return PortResult(port, "tcp", "open", banner="(no banner)",
                              latency_ms=elapsed)

    except socket.timeout:
        return PortResult(port, "tcp", "filtered",
                          latency_ms=(time.monotonic() - t0) * 1000)
    except ConnectionRefusedError:
        return PortResult(port, "tcp", "closed",
                          latency_ms=(time.monotonic() - t0) * 1000)
    except OSError:
        return PortResult(port, "tcp", "filtered",
                          latency_ms=(time.monotonic() - t0) * 1000)


def scan_tcp_ports(host: str, ports: list[int],
                   timeout: float = 3.0) -> list[PortResult]:
    """Scan multiple TCP ports sequentially."""
    results = []
    for port in ports:
        r = scan_tcp_port(host, port, timeout)
        results.append(r)
        if r.state in ("open", "rst"):
            print(f"  {'✓' if r.state == 'open' else '⚡'} TCP/{port:<5d}  "
                  f"{r.state:8s}  {r.latency_ms:6.0f}ms  {r.banner}")
    return results


# ---------------------------------------------------------------------------
# UDP port probe
# ---------------------------------------------------------------------------

_UDP_PAYLOADS = {
    53: (  # DNS A query for megared.net.mx
        b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07megared\x03net\x02mx\x00\x00\x01\x00\x01"
    ),
    123: b"\x1b" + b"\x00" * 47,  # NTP version request
    161: (  # SNMP v1 get-request (public community)
        b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19"
        b"\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00"
        b"\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
    ),
    5060: b"OPTIONS sip:test SIP/2.0\r\nVia: SIP/2.0/UDP probe\r\n\r\n",
}


def probe_udp_port(host: str, port: int, timeout: float = 3.0) -> PortResult:
    """Send a UDP probe and check for a response."""
    payload = _UDP_PAYLOADS.get(port, b"\x00" * 8)
    t0 = time.monotonic()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(payload, (host, port))
        data, _addr = s.recvfrom(1024)
        elapsed = (time.monotonic() - t0) * 1000
        s.close()
        banner = f"response: {len(data)} bytes"
        return PortResult(port, "udp", "open", banner=banner,
                          latency_ms=elapsed)
    except socket.timeout:
        elapsed = (time.monotonic() - t0) * 1000
        return PortResult(port, "udp", "open|filtered", latency_ms=elapsed)
    except OSError as e:
        elapsed = (time.monotonic() - t0) * 1000
        if "refused" in str(e).lower():
            return PortResult(port, "udp", "closed", latency_ms=elapsed)
        return PortResult(port, "udp", "filtered", latency_ms=elapsed)


def scan_udp_ports(host: str, ports: list[int],
                   timeout: float = 3.0) -> list[PortResult]:
    """Probe multiple UDP ports."""
    results = []
    for port in ports:
        r = probe_udp_port(host, port, timeout)
        results.append(r)
        if r.state == "open":
            print(f"  ✓ UDP/{port:<5d}  {r.state:15s}  {r.banner}")
    return results


# ---------------------------------------------------------------------------
# TCP handshake analysis
# ---------------------------------------------------------------------------

def analyze_tcp_handshake(host: str, port: int = 80,
                          attempts: int = 3) -> dict:
    """
    Perform repeated TCP connections to measure handshake timing and
    determine whether the server sends RST immediately after SYN-ACK.
    """
    results = {
        "port": port,
        "attempts": [],
        "pattern": "",
    }

    for i in range(attempts):
        attempt = {"n": i + 1}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            t0 = time.monotonic()
            s.connect((host, port))
            t1 = time.monotonic()
            attempt["handshake_ms"] = round((t1 - t0) * 1000, 1)
            attempt["handshake"] = "ok"

            try:
                s.settimeout(2)
                data = s.recv(1)
                attempt["after_handshake"] = f"data: {data!r}"
            except ConnectionResetError:
                t2 = time.monotonic()
                attempt["after_handshake"] = "RST"
                attempt["rst_delay_ms"] = round((t2 - t1) * 1000, 1)
            except socket.timeout:
                attempt["after_handshake"] = "timeout (server waiting)"
            s.close()
        except Exception as e:
            attempt["handshake"] = "failed"
            attempt["error"] = str(e)

        results["attempts"].append(attempt)
        time.sleep(0.3)

    # Determine pattern
    rst_count = sum(1 for a in results["attempts"]
                    if a.get("after_handshake") == "RST")
    if rst_count == attempts:
        results["pattern"] = "immediate_rst_after_handshake"
        results["interpretation"] = (
            "Server completes TCP handshake then immediately sends RST. "
            "This indicates an IP-based whitelist (firewall/load-balancer) "
            "that only accepts connections from MEGACABLE subscriber IPs. "
            "The port is open at the TCP level but the application layer "
            "rejects non-whitelisted sources."
        )
    elif rst_count > 0:
        results["pattern"] = "intermittent_rst"
    else:
        results["pattern"] = "normal"

    return results


# ---------------------------------------------------------------------------
# HTTP probing (with connection-reset bypass strategies)
# ---------------------------------------------------------------------------

def probe_http(host: str, ip: str, port: int = 80) -> list[HttpProbeResult]:
    """
    Try multiple HTTP strategies to get a response from the ACS.

    The server resets browser connections but may accept:
    - CWMP User-Agent strings
    - TR-069 SOAP POST requests
    - Direct IP access
    - Different ports
    """
    if requests is None:
        return []

    results: list[HttpProbeResult] = []

    schemes = ["http"] if port in (80, 8080, 7547) else ["https"]
    targets = [
        f"{schemes[0]}://{host}:{port}/",
        f"{schemes[0]}://{host}:{port}/service/cwmp",
        f"{schemes[0]}://{ip}:{port}/",
        f"{schemes[0]}://{ip}:{port}/service/cwmp",
    ]

    # GET probes with different UAs
    for ua in _USER_AGENTS[:3]:
        for url in targets[:2]:
            r = HttpProbeResult(url=url, method="GET", user_agent=ua)
            try:
                resp = requests.get(
                    url, timeout=6, verify=False, allow_redirects=False,
                    headers={"User-Agent": ua},
                )
                r.status_code = resp.status_code
                r.server = resp.headers.get("Server", "")
                r.content_type = resp.headers.get("Content-Type", "")
                r.content_length = len(resp.content)
                r.redirect = resp.headers.get("Location", "")
                r.body_preview = resp.text[:150].replace("\n", " ")
            except Exception as e:
                r.error = str(e)[:100]
            results.append(r)

    # TR-069 CWMP Inform POST
    cwmp_inform = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"'
        ' xmlns:cwmp="urn:dslforum-org:cwmp-1-0">'
        "<soap:Header>"
        '<cwmp:ID soap:mustUnderstand="1">1</cwmp:ID>'
        "</soap:Header>"
        "<soap:Body>"
        "<cwmp:Inform>"
        "<DeviceId>"
        "<Manufacturer>Huawei</Manufacturer>"
        "<OUI>00E0FC</OUI>"
        "<ProductClass>HG8145V5</ProductClass>"
        "<SerialNumber>HWTC00000000</SerialNumber>"
        "</DeviceId>"
        "<Event><EventStruct>"
        "<EventCode>0 BOOTSTRAP</EventCode>"
        "</EventStruct></Event>"
        "<MaxEnvelopes>1</MaxEnvelopes>"
        f"<CurrentTime>{datetime.now(timezone.utc).isoformat()}</CurrentTime>"
        "<RetryCount>0</RetryCount>"
        "<ParameterList></ParameterList>"
        "</cwmp:Inform>"
        "</soap:Body>"
        "</soap:Envelope>"
    )

    for url in [f"http://{host}:{port}/service/cwmp",
                f"http://{ip}:{port}/service/cwmp"]:
        r = HttpProbeResult(
            url=url, method="POST",
            user_agent="Huawei HG8145V5 CWMP/1.0",
        )
        try:
            resp = requests.post(
                url, data=cwmp_inform, timeout=8, verify=False,
                headers={
                    "Content-Type": "text/xml; charset=utf-8",
                    "SOAPAction": '""',
                    "User-Agent": "Huawei HG8145V5 V500R022C00SPC368 CWMP/1.0",
                },
            )
            r.status_code = resp.status_code
            r.server = resp.headers.get("Server", "")
            r.content_type = resp.headers.get("Content-Type", "")
            r.content_length = len(resp.content)
            r.body_preview = resp.text[:150].replace("\n", " ")
        except Exception as e:
            r.error = str(e)[:100]
        results.append(r)

    return results


def probe_firmware_files(host: str, ip: str,
                         port: int = 80) -> list[HttpProbeResult]:
    """
    Probe for .bin firmware files on the ACS.

    Megacable pushes firmware updates to Huawei ONTs via TR-069
    Download RPC pointing at URLs on the ACS.
    """
    if requests is None:
        return []

    results: list[HttpProbeResult] = []
    scheme = "http" if port in (80, 8080, 7547) else "https"

    for base_path in FIRMWARE_PATHS:
        for bin_file in FIRMWARE_BIN_FILES:
            url = f"{scheme}://{host}:{port}{base_path}{bin_file}"
            r = HttpProbeResult(
                url=url, method="HEAD",
                user_agent="Huawei HG8145V5 CWMP/1.0",
            )
            try:
                resp = requests.head(
                    url, timeout=5, verify=False, allow_redirects=True,
                    headers={
                        "User-Agent": "Huawei HG8145V5 V500R022C00SPC368 CWMP/1.0",
                    },
                )
                r.status_code = resp.status_code
                r.server = resp.headers.get("Server", "")
                r.content_type = resp.headers.get("Content-Type", "")
                cl = resp.headers.get("Content-Length", "")
                r.content_length = int(cl) if cl.isdigit() else 0
                r.redirect = resp.headers.get("Location", "")
                if r.status_code < 400:
                    print(f"  ✓ [{r.status_code}] {url}  "
                          f"({r.content_length} bytes, {r.content_type})")
            except Exception as e:
                r.error = str(e)[:80]
            results.append(r)

    return results


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def run_analysis(
    tcp_ports: list[int] | None = None,
    udp_ports: list[int] | None = None,
    scan_udp: bool = False,
    probe_fw: bool = True,
    tcp_timeout: float = 3.0,
    output_json: str | None = None,
) -> AnalysisReport:
    """Run the full analysis and return a report."""
    report = AnalysisReport()
    report.timestamp = datetime.now(timezone.utc).isoformat()

    if tcp_ports is None:
        tcp_ports = DEFAULT_TCP_PORTS

    # --- DNS ---
    print("=" * 60)
    print(f"acsvip.megared.net.mx — Deep Analysis")
    print("=" * 60)
    print()
    print("Phase 1: DNS Resolution")
    print("-" * 40)
    ipv4, ipv6, rdns = resolve_host(TARGET_HOST)
    report.ipv4 = ipv4
    report.ipv6 = ipv6
    report.reverse_dns = rdns
    print(f"  IPv4        : {ipv4 or '(none)'}")
    print(f"  IPv6        : {ipv6 or '(none)'}")
    print(f"  Reverse DNS : {rdns or '(none)'}")

    if not ipv4:
        report.summary = "Host does not resolve — cannot scan."
        print(f"\n{report.summary}")
        return report

    # --- TCP Handshake Analysis ---
    print()
    print("Phase 2: TCP Handshake Analysis (port 80)")
    print("-" * 40)
    report.tcp_handshake = analyze_tcp_handshake(ipv4, port=80)
    pattern = report.tcp_handshake.get("pattern", "")
    interp = report.tcp_handshake.get("interpretation", "")
    for a in report.tcp_handshake.get("attempts", []):
        hs_ms = a.get("handshake_ms", "?")
        after = a.get("after_handshake", "?")
        rst_ms = a.get("rst_delay_ms", "")
        rst_info = f" ({rst_ms}ms)" if rst_ms else ""
        print(f"  Attempt {a['n']}: handshake={hs_ms}ms  "
              f"after={after}{rst_info}")
    print(f"  Pattern: {pattern}")
    if interp:
        print(f"  → {interp}")

    # --- TCP Port Scan ---
    print()
    print(f"Phase 3: TCP Port Scan ({len(tcp_ports)} ports)")
    print("-" * 40)
    report.tcp_ports = scan_tcp_ports(ipv4, tcp_ports, tcp_timeout)
    open_tcp = [p for p in report.tcp_ports if p.state == "open"]
    rst_tcp = [p for p in report.tcp_ports if p.state == "rst"]
    print(f"\n  Open: {len(open_tcp)}  |  RST (whitelisted): {len(rst_tcp)}  |  "
          f"Filtered/Closed: {len(tcp_ports) - len(open_tcp) - len(rst_tcp)}")

    # --- UDP Port Scan ---
    if scan_udp:
        if udp_ports is None:
            udp_ports = DEFAULT_UDP_PORTS
        print()
        print(f"Phase 4: UDP Port Probe ({len(udp_ports)} ports)")
        print("-" * 40)
        report.udp_ports = scan_udp_ports(ipv4, udp_ports)
        open_udp = [p for p in report.udp_ports if p.state == "open"]
        print(f"\n  Confirmed open: {len(open_udp)}  |  "
              f"open|filtered: "
              f"{sum(1 for p in report.udp_ports if p.state == 'open|filtered')}")
    else:
        print()
        print("Phase 4: UDP scan skipped (use --udp to enable)")

    # --- HTTP Probes ---
    print()
    print("Phase 5: HTTP Probing (multiple strategies)")
    print("-" * 40)
    for port in (80, 7547, 8080, 443):
        if any(p.port == port and p.state in ("open", "rst")
               for p in report.tcp_ports):
            probes = probe_http(ipv4, ipv4, port)
            report.http_probes.extend(probes)
            for p in probes:
                status = f"[{p.status_code}]" if p.status_code else "[ERR]"
                detail = p.error[:60] if p.error else p.body_preview[:60]
                print(f"  {status:5s} {p.method:4s} {p.url[:55]:55s}  {detail}")

    # --- Firmware .bin probes ---
    if probe_fw:
        print()
        print("Phase 6: Firmware .bin File Probes")
        print("-" * 40)
        report.firmware_probes = probe_firmware_files(TARGET_HOST, ipv4)
        found = [p for p in report.firmware_probes if p.status_code and p.status_code < 400]
        rst_fw = [p for p in report.firmware_probes if "reset" in (p.error or "").lower()]
        print(f"\n  Accessible: {len(found)}  |  "
              f"Connection reset: {len(rst_fw)}  |  "
              f"Total probed: {len(report.firmware_probes)}")

    # --- Summary ---
    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)

    summary_lines = [
        f"Target: {TARGET_HOST} ({ipv4})",
        f"Reverse DNS: {rdns}",
        f"TCP pattern: {pattern}",
    ]
    if open_tcp:
        summary_lines.append(
            f"Open TCP ports: {', '.join(str(p.port) for p in open_tcp)}")
    if rst_tcp:
        summary_lines.append(
            f"RST (IP-whitelisted) TCP ports: "
            f"{', '.join(str(p.port) for p in rst_tcp)}")
    if not open_tcp and rst_tcp:
        summary_lines.append(
            "All open ports send immediate RST after TCP handshake. "
            "The ACS firewall whitelists connections by source IP — "
            "only MEGACABLE subscriber IPs (201.159.x.x range) can "
            "reach the application layer. Firmware .bin files are "
            "served via TR-069 Download RPC to whitelisted ONTs only."
        )

    report.summary = "\n".join(summary_lines)
    for line in summary_lines:
        print(f"  {line}")
    print("=" * 60)

    # --- Save ---
    if output_json:
        path = report.save(Path(output_json))
        print(f"\nReport saved to: {path}")

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Deep analysis of acsvip.megared.net.mx (MEGACABLE ACS)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python acsvip_analysis.py\n"
            "  python acsvip_analysis.py --udp\n"
            "  python acsvip_analysis.py --tcp-range 1-1024\n"
            "  python acsvip_analysis.py --json report.json\n"
        ),
    )
    parser.add_argument(
        "--tcp-range", default=None,
        help="TCP port range to scan (e.g. '1-1024'). Default: common ports.",
    )
    parser.add_argument(
        "--udp", action="store_true", default=False,
        help="Enable UDP port probing",
    )
    parser.add_argument(
        "--no-firmware", action="store_true", default=False,
        help="Skip firmware .bin file probing",
    )
    parser.add_argument(
        "--timeout", type=float, default=3.0,
        help="TCP probe timeout in seconds (default: 3.0)",
    )
    parser.add_argument(
        "--json", dest="json_output", default=None,
        help="Save report as JSON to the given path",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    tcp_ports = None
    if args.tcp_range:
        parts = args.tcp_range.split("-")
        if len(parts) == 2:
            tcp_ports = list(range(int(parts[0]), int(parts[1]) + 1))
        else:
            tcp_ports = [int(p) for p in args.tcp_range.split(",")]

    run_analysis(
        tcp_ports=tcp_ports,
        scan_udp=args.udp,
        probe_fw=not args.no_firmware,
        tcp_timeout=args.timeout,
        output_json=args.json_output,
    )


if __name__ == "__main__":
    main()
