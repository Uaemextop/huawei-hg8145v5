#!/usr/bin/env python3
"""
Huawei HiCloud Firmware Update Server Scanner
==============================================
Advanced scanner for Huawei's firmware update infrastructure at
``update.hicloud.com`` and related CDN hosts.

Features
--------
- Multi-port TCP/UDP scanning (8180, 80, 443, 8080, 8443, …)
- Multi-method HTTP probing (GET, POST, HEAD, OPTIONS) with firmware UAs
- Path dictionary from known Huawei HiCloud URL patterns + GitHub wordlists
- File-index discovery (directory listing, filename brute-force)
- HG8145V5 / HG8145V5-12 specific firmware search
- Firmware download attempt for discovered files
- JSON report output

Usage
-----
    python hicloud_scanner.py
    python hicloud_scanner.py --scan-ports
    python hicloud_scanner.py --download-dir ./firmware_downloads
    python hicloud_scanner.py --json results.json
    python hicloud_scanner.py --fast          # skip slow scans
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Target configuration
# ---------------------------------------------------------------------------
TARGET_HOST = "update.hicloud.com"
# Primary URL from the issue — Huawei firmware TDS (Telecom Delivery System)
BASE_URL = "http://update.hicloud.com:8180/TDS/data/files/p9/s115/G345/g0/v10149/f1/full/"

# Known Huawei firmware update hosts (CDN mirrors and regional servers)
HICLOUD_HOSTS = [
    "update.hicloud.com",
    "update.dbankcloud.com",
    "query.hicloud.com",
    "store.hicloud.com",
    "appstore.huawei.com",
    "consumer.huawei.com",
    "download.huawei.com",
    "devcenter-test.huawei.com",
    "support.huawei.com",
    "update.huaweicloud.com",
]

# Ports to scan
DEFAULT_TCP_PORTS = [
    80, 443, 8080, 8180, 8443, 8888, 9090,
    # Standard services
    21, 22, 23, 25, 53, 110, 143, 445, 993, 995,
    # Alternative HTTP/HTTPS
    81, 82, 88, 280, 591, 631, 808, 2082, 2083, 2086, 2087,
    3000, 4443, 5000, 5443, 6443, 7000, 7070, 7443, 7547,
    8000, 8001, 8002, 8008, 8009, 8010, 8081, 8082, 8083,
    8085, 8090, 8181, 8280, 8443, 8530, 8880, 8888, 9000,
    9043, 9060, 9080, 9090, 9091, 9200, 9443, 9999,
    10000, 10443, 18080, 18443,
]

DEFAULT_UDP_PORTS = [
    53, 67, 68, 69, 123, 161, 162, 500, 514, 1194,
    1701, 1812, 1813, 4500, 5060, 8180,
]

# ---------------------------------------------------------------------------
# Firmware-extracted User-Agent strings (from EG8145V5 rootfs)
# ---------------------------------------------------------------------------
USER_AGENTS = [
    # Main CWMP session UA (libhw_smp_cwmp_core.so)
    "HuaweiHomeGateway",
    # Bulk data upload UA (libhw_cwmp_bulkchina.so)
    "HW-FTTH",
    # IP/MAC report UA (libhw_cwmp_china_pdt.so)
    "HW_IPMAC_REPORT",
    # HTTP client UA (libhw_smp_httpclient.so)
    (
        "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; "
        "Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; "
        ".NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0E; .NET4.0C)"
    ),
    # Web market UA (libhw_smp_base.so)
    (
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; "
        "Trident/5.0; 2345Explorer)"
    ),
    # Huawei HiApp client
    "HiApp/10.0 (HuaweiMobile; Android 10; HG8145V5)",
    # Standard browsers
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "curl/8.4.0",
    "Wget/1.21",
    # Python requests default
    "python-requests/2.31.0",
]

# ---------------------------------------------------------------------------
# HiCloud TDS URL patterns
# ---------------------------------------------------------------------------
# Huawei's TDS (Telecom Delivery System) uses structured URL paths:
#   /TDS/data/files/p{product}/s{series}/G{group}/g{subgroup}/v{version}/f{file}/full/
#
# Known patterns for ONT firmware:
#   p9  = Huawei Home Gateway / ONT products
#   s115 = HG8145V5 series (also s116, s117 for variants)
#   G345 = Group identifier (varies by region/ISP)
#   g0   = Subgroup (usually 0)
#   v10149 = Version identifier (maps to SPC version)
#   f1   = File number (usually 1 for single firmware)
#   full/ = Full firmware image (vs. incremental/diff)

# Base TDS path components to try (dynamically generated from wordlists)
TDS_PRODUCTS: list[str] = []
TDS_SERIES: list[str] = []
TDS_GROUPS: list[str] = []
TDS_VERSIONS: list[str] = []
TDS_FILES: list[str] = []
TDS_TYPES: list[str] = []

# ---------------------------------------------------------------------------
# Path dictionaries — populated dynamically from downloaded GitHub wordlists.
# No hardcoded paths: all discovery is driven by wordlists at runtime.

COMMON_PATHS: list[str] = []

INDEX_FILENAMES: list[str] = []

# Firmware filenames — dynamically built from wordlist content at runtime
HG8145V5_FIRMWARE_FILES: list[str] = []

# GitHub wordlists commonly used for web directory fuzzing
GITHUB_WORDLISTS = {
    "description": "Well-known directory/file wordlists from GitHub security tools",
    "sources": [
        "https://github.com/danielmiessler/SecLists (Discovery/Web-Content)",
        "https://github.com/fuzzdb-project/fuzzdb (discovery/predictable-filepaths)",
        "https://github.com/Bo0oM/fuzz.txt",
        "https://github.com/six2dez/OneListForAll",
    ],
    # Raw download URLs for real wordlists (small/medium size for speed)
    "download_urls": [
        # SecLists — common web content discovery
        (
            "https://raw.githubusercontent.com/danielmiessler/SecLists"
            "/master/Discovery/Web-Content/common.txt"
        ),
        # SecLists — directory listing filenames
        (
            "https://raw.githubusercontent.com/danielmiessler/SecLists"
            "/master/Discovery/Web-Content/directory-list-2.3-small.txt"
        ),
        # SecLists — raft filenames (common index/default files)
        (
            "https://raw.githubusercontent.com/danielmiessler/SecLists"
            "/master/Discovery/Web-Content/raft-small-files.txt"
        ),
        # SecLists — raft directories
        (
            "https://raw.githubusercontent.com/danielmiessler/SecLists"
            "/master/Discovery/Web-Content/raft-small-directories.txt"
        ),
        # fuzzdb — common file names
        (
            "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb"
            "/master/discovery/predictable-filepaths/"
            "filename-dirname-bruteforce/raft-small-files.txt"
        ),
        # Bo0oM fuzz.txt — single consolidated wordlist
        "https://raw.githubusercontent.com/Bo0oM/fuzz.txt/master/fuzz.txt",
    ],
    # Curated subset removed — all paths come from downloaded wordlists
    "paths": [],
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PortResult:
    """Result of a single port scan."""
    host: str
    port: int
    protocol: str     # "tcp" or "udp"
    state: str        # "open", "closed", "filtered", "rst"
    banner: str = ""
    latency_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "banner": self.banner,
            "latency_ms": round(self.latency_ms, 1),
        }


@dataclass
class HttpProbeResult:
    """Result of an HTTP probe."""
    url: str
    method: str
    user_agent: str
    status_code: int = 0
    server: str = ""
    content_type: str = ""
    content_length: int = 0
    headers: dict = field(default_factory=dict)
    body_preview: str = ""
    error: str = ""
    redirect: str = ""
    latency_ms: float = 0.0

    def to_dict(self) -> dict:
        d = {
            "url": self.url,
            "method": self.method,
            "user_agent": self.user_agent[:50],
            "status_code": self.status_code,
            "latency_ms": round(self.latency_ms, 1),
        }
        if self.server:
            d["server"] = self.server
        if self.content_type:
            d["content_type"] = self.content_type
        if self.content_length:
            d["content_length"] = self.content_length
        if self.body_preview:
            d["body_preview"] = self.body_preview[:200]
        if self.error:
            d["error"] = self.error
        if self.redirect:
            d["redirect"] = self.redirect
        if self.headers:
            d["headers"] = dict(self.headers)
        return d


@dataclass
class FirmwareCandidate:
    """A potential firmware file found on the server."""
    url: str
    filename: str
    status_code: int = 0
    content_type: str = ""
    content_length: int = 0
    server: str = ""
    is_downloadable: bool = False
    sha256: str = ""
    download_path: str = ""

    def to_dict(self) -> dict:
        d = {
            "url": self.url,
            "filename": self.filename,
            "status_code": self.status_code,
            "is_downloadable": self.is_downloadable,
        }
        if self.content_type:
            d["content_type"] = self.content_type
        if self.content_length:
            d["content_length"] = self.content_length
        if self.server:
            d["server"] = self.server
        if self.sha256:
            d["sha256"] = self.sha256
        if self.download_path:
            d["download_path"] = self.download_path
        return d


@dataclass
class NmapResult:
    """Result of an nmap scan."""
    command: str = ""
    host: str = ""
    scan_type: str = ""        # "port_scan", "vuln_scan", "service_detect"
    open_ports: list = field(default_factory=list)
    services: list = field(default_factory=list)
    vulnerabilities: list = field(default_factory=list)
    os_detection: str = ""
    raw_output: str = ""
    xml_output: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        d = {
            "command": self.command,
            "host": self.host,
            "scan_type": self.scan_type,
        }
        if self.open_ports:
            d["open_ports"] = self.open_ports
        if self.services:
            d["services"] = self.services
        if self.vulnerabilities:
            d["vulnerabilities"] = self.vulnerabilities
        if self.os_detection:
            d["os_detection"] = self.os_detection
        if self.error:
            d["error"] = self.error
        # raw_output/xml_output omitted from dict for brevity
        return d


@dataclass
class ScanReport:
    """Full scan report for Huawei HiCloud firmware server."""
    timestamp: str = ""
    target: str = TARGET_HOST
    base_url: str = BASE_URL
    resolved_ips: list = field(default_factory=list)
    tcp_ports: list = field(default_factory=list)
    udp_ports: list = field(default_factory=list)
    http_probes: list = field(default_factory=list)
    path_discovery: list = field(default_factory=list)
    index_files: list = field(default_factory=list)
    firmware_candidates: list = field(default_factory=list)
    tds_probes: list = field(default_factory=list)
    nmap_results: list = field(default_factory=list)
    wordlists_downloaded: list = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "target": self.target,
            "base_url": self.base_url,
            "resolved_ips": self.resolved_ips,
            "tcp_ports": [p.to_dict() if hasattr(p, 'to_dict') else p
                          for p in self.tcp_ports],
            "udp_ports": [p.to_dict() if hasattr(p, 'to_dict') else p
                          for p in self.udp_ports],
            "http_probes_count": len(self.http_probes),
            "http_probes": [p.to_dict() if hasattr(p, 'to_dict') else p
                            for p in self.http_probes],
            "path_discovery_count": len(self.path_discovery),
            "path_discovery": [p.to_dict() if hasattr(p, 'to_dict') else p
                               for p in self.path_discovery],
            "index_files": [p.to_dict() if hasattr(p, 'to_dict') else p
                            for p in self.index_files],
            "firmware_candidates": [f.to_dict() if hasattr(f, 'to_dict') else f
                                    for f in self.firmware_candidates],
            "tds_probes_count": len(self.tds_probes),
            "tds_probes": [p.to_dict() if hasattr(p, 'to_dict') else p
                           for p in self.tds_probes],
            "nmap_results": [n.to_dict() if hasattr(n, 'to_dict') else n
                             for n in self.nmap_results],
            "wordlists_downloaded": self.wordlists_downloaded,
            "summary": self.summary,
        }

    def save(self, path: Path) -> Path:
        """Save report as JSON."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return path

    def print_summary(self) -> None:
        """Print human-readable summary."""
        print("=" * 70)
        print("Huawei HiCloud Firmware Server Scan Report")
        print("=" * 70)
        print(f"  Timestamp : {self.timestamp}")
        print(f"  Target    : {self.target}")
        print(f"  Base URL  : {self.base_url}")
        if self.resolved_ips:
            print(f"  IPs       : {', '.join(self.resolved_ips)}")
        print()

        if self.tcp_ports:
            open_tcp = [p for p in self.tcp_ports
                        if (p.state if hasattr(p, 'state') else p.get('state', '')) == 'open']
            print(f"TCP Ports Scanned : {len(self.tcp_ports)}")
            print(f"  Open            : {len(open_tcp)}")
            for p in open_tcp:
                port = p.port if hasattr(p, 'port') else p.get('port', '?')
                banner = p.banner if hasattr(p, 'banner') else p.get('banner', '')
                print(f"    {port:5d}/tcp  open  {banner}")
            print()

        if self.http_probes:
            ok = [p for p in self.http_probes
                  if (p.status_code if hasattr(p, 'status_code')
                      else p.get('status_code', 0)) in range(200, 400)]
            print(f"HTTP Probes       : {len(self.http_probes)}")
            print(f"  Successful (2xx/3xx) : {len(ok)}")
            for p in ok[:10]:
                url = p.url if hasattr(p, 'url') else p.get('url', '')
                code = p.status_code if hasattr(p, 'status_code') else p.get('status_code', 0)
                print(f"    [{code}] {url}")
            print()

        if self.firmware_candidates:
            downloadable = [f for f in self.firmware_candidates
                            if (f.is_downloadable if hasattr(f, 'is_downloadable')
                                else f.get('is_downloadable', False))]
            print(f"Firmware Candidates: {len(self.firmware_candidates)}")
            print(f"  Downloadable     : {len(downloadable)}")
            for fw in self.firmware_candidates:
                fn = fw.filename if hasattr(fw, 'filename') else fw.get('filename', '?')
                code = fw.status_code if hasattr(fw, 'status_code') else fw.get('status_code', 0)
                dl = fw.is_downloadable if hasattr(fw, 'is_downloadable') else fw.get('is_downloadable', False)
                size = fw.content_length if hasattr(fw, 'content_length') else fw.get('content_length', 0)
                status = "✓ DOWNLOAD" if dl else f"[{code}]"
                size_str = f" ({size:,} bytes)" if size else ""
                print(f"    {status} {fn}{size_str}")
            print()

        if self.nmap_results:
            print(f"Nmap Scans: {len(self.nmap_results)}")
            for nr in self.nmap_results:
                st = nr.scan_type if hasattr(nr, 'scan_type') else nr.get('scan_type', '')
                host = nr.host if hasattr(nr, 'host') else nr.get('host', '')
                ports = nr.open_ports if hasattr(nr, 'open_ports') else nr.get('open_ports', [])
                vulns = nr.vulnerabilities if hasattr(nr, 'vulnerabilities') else nr.get('vulnerabilities', [])
                svcs = nr.services if hasattr(nr, 'services') else nr.get('services', [])
                err = nr.error if hasattr(nr, 'error') else nr.get('error', '')
                print(f"  [{st}] {host}")
                if ports:
                    print(f"    Open ports: {len(ports)}")
                    for p in ports[:20]:
                        print(f"      {p}")
                if svcs:
                    print(f"    Services: {len(svcs)}")
                    for s in svcs[:10]:
                        print(f"      {s}")
                if vulns:
                    print(f"    Vulnerabilities: {len(vulns)}")
                    for v in vulns:
                        print(f"      ⚠ {v}")
                if err:
                    print(f"    Error: {err}")
            print()

        if self.wordlists_downloaded:
            print(f"Wordlists Downloaded: {len(self.wordlists_downloaded)}")
            for wl in self.wordlists_downloaded:
                print(f"  {wl}")
            print()

        if self.summary:
            print(self.summary)
        print("=" * 70)


# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------

def resolve_host(host: str) -> list[str]:
    """Resolve hostname to IP addresses."""
    ips = []
    try:
        results = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        seen = set()
        for family, _, _, _, sockaddr in results:
            ip = sockaddr[0]
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
    except socket.gaierror:
        pass
    return ips


# ---------------------------------------------------------------------------
# Port scanning
# ---------------------------------------------------------------------------

def scan_tcp_port(host: str, port: int, timeout: float = 3.0) -> PortResult:
    """Scan a single TCP port."""
    result = PortResult(host=host, port=port, protocol="tcp", state="filtered")
    try:
        t0 = time.monotonic()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        err = sock.connect_ex((host, port))
        elapsed = (time.monotonic() - t0) * 1000
        result.latency_ms = elapsed
        if err == 0:
            result.state = "open"
            # Try to grab a banner
            try:
                sock.settimeout(2.0)
                sock.sendall(b"\r\n")
                banner = sock.recv(1024)
                result.banner = banner.decode("utf-8", errors="replace").strip()[:200]
            except (socket.timeout, OSError):
                pass
        else:
            result.state = "closed"
        sock.close()
    except socket.timeout:
        result.state = "filtered"
    except ConnectionRefusedError:
        result.state = "closed"
    except ConnectionResetError:
        result.state = "rst"
    except OSError:
        result.state = "filtered"
    return result


def scan_udp_port(host: str, port: int, timeout: float = 3.0) -> PortResult:
    """Probe a single UDP port."""
    result = PortResult(host=host, port=port, protocol="udp", state="open|filtered")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        # Send a minimal probe
        probe = b"\x00" * 8
        if port == 53:
            # DNS query for update.hicloud.com
            probe = (
                b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x06update\x07hicloud\x03com\x00\x00\x01\x00\x01"
            )
        elif port == 123:
            # NTP request
            probe = b"\x1b" + b"\x00" * 47

        t0 = time.monotonic()
        sock.sendto(probe, (host, port))
        try:
            data, _ = sock.recvfrom(4096)
            elapsed = (time.monotonic() - t0) * 1000
            result.state = "open"
            result.latency_ms = elapsed
            result.banner = f"{len(data)} bytes response"
        except socket.timeout:
            result.state = "open|filtered"
        sock.close()
    except OSError:
        result.state = "filtered"
    return result


def scan_ports(host: str, tcp_ports: list[int], udp_ports: list[int],
               verbose: bool = False) -> tuple[list[PortResult], list[PortResult]]:
    """Scan TCP and UDP ports on a host."""
    tcp_results = []
    udp_results = []

    ip = host
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        pass

    if verbose:
        print(f"\n[*] Scanning {len(tcp_ports)} TCP ports on {host} ({ip})...")
    for port in tcp_ports:
        r = scan_tcp_port(ip, port)
        tcp_results.append(r)
        if r.state == "open" and verbose:
            print(f"  [+] {port}/tcp OPEN  {r.banner[:60]}")

    if udp_ports:
        if verbose:
            print(f"\n[*] Probing {len(udp_ports)} UDP ports on {host} ({ip})...")
        for port in udp_ports:
            r = scan_udp_port(ip, port)
            udp_results.append(r)
            if r.state == "open" and verbose:
                print(f"  [+] {port}/udp OPEN  {r.banner[:60]}")

    return tcp_results, udp_results


# ---------------------------------------------------------------------------
# Nmap integration
# ---------------------------------------------------------------------------

def _nmap_available() -> bool:
    """Check if nmap is installed."""
    return shutil.which("nmap") is not None


def _parse_nmap_xml(xml_str: str) -> dict:
    """Parse nmap XML output into structured data."""
    result: dict = {"ports": [], "services": [], "scripts": [], "os": ""}
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return result

    # Extract host info
    for host_el in root.findall(".//host"):
        # OS detection
        for osmatch in host_el.findall(".//osmatch"):
            result["os"] = osmatch.get("name", "")
            break

        # Ports and services
        for port_el in host_el.findall(".//port"):
            portid = port_el.get("portid", "")
            protocol = port_el.get("protocol", "")
            state_el = port_el.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            service_el = port_el.find("service")
            svc_name = service_el.get("name", "") if service_el is not None else ""
            svc_product = service_el.get("product", "") if service_el is not None else ""
            svc_version = service_el.get("version", "") if service_el is not None else ""

            if state == "open":
                result["ports"].append(f"{portid}/{protocol}")
                svc_str = svc_name
                if svc_product:
                    svc_str += f" ({svc_product}"
                    if svc_version:
                        svc_str += f" {svc_version}"
                    svc_str += ")"
                result["services"].append(f"{portid}/{protocol} {svc_str}")

            # NSE script results (vulnerabilities)
            for script_el in port_el.findall("script"):
                sid = script_el.get("id", "")
                output = script_el.get("output", "")
                result["scripts"].append({
                    "port": f"{portid}/{protocol}",
                    "script": sid,
                    "output": output.strip()[:500],
                })

        # Host-level scripts
        for script_el in host_el.findall(".//hostscript/script"):
            sid = script_el.get("id", "")
            output = script_el.get("output", "")
            result["scripts"].append({
                "port": "host",
                "script": sid,
                "output": output.strip()[:500],
            })

    return result


def run_nmap_scan(host: str, scan_type: str = "port_scan",
                  ports: str = "-", timeout: int = 300,
                  verbose: bool = False) -> NmapResult:
    """Run an nmap scan against a host.

    Parameters
    ----------
    host : str
        Target hostname or IP.
    scan_type : str
        One of ``"port_scan"`` (TCP SYN + service detection),
        ``"vuln_scan"`` (NSE vulnerability scripts), or
        ``"full_scan"`` (both combined).
    ports : str
        Port specification (``"-"`` = all 65535, ``"1-1024"`` = range).
    timeout : int
        Maximum seconds to wait for nmap to finish.
    verbose : bool
        Print progress.
    """
    if not _nmap_available():
        return NmapResult(host=host, scan_type=scan_type,
                          error="nmap not installed")

    result = NmapResult(host=host, scan_type=scan_type)

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        xml_path = tmp.name

    try:
        # Build nmap command
        cmd = ["nmap"]

        if scan_type == "port_scan":
            # SYN scan + service version + OS detection on all ports
            cmd += [
                "-sS", "-sV",              # SYN scan + service version
                "-p", ports,                # port range (- = all)
                "--open",                   # only show open ports
                "-T4",                      # aggressive timing
                "--max-retries", "2",
                "-oX", xml_path,            # XML output
            ]
        elif scan_type == "vuln_scan":
            # Vulnerability scanning with NSE scripts
            cmd += [
                "-sV",                      # service version (needed by scripts)
                "-p", ports,
                "--script", (
                    "vuln,"                         # all vuln category scripts
                    "http-enum,"                    # enumerate web directories
                    "http-headers,"                 # grab HTTP headers
                    "http-methods,"                 # check allowed methods
                    "http-title,"                   # page titles
                    "http-server-header,"           # server identification
                    "http-robots.txt,"              # robots.txt
                    "ssl-cert,"                     # TLS certificate info
                    "ssl-enum-ciphers,"             # cipher enumeration
                    "http-vuln-cve2017-5638,"       # Apache Struts RCE
                    "http-vuln-cve2014-3120,"       # Elasticsearch RCE
                    "http-shellshock"               # Shellshock
                ),
                "--script-timeout", "30s",
                "-T4",
                "--max-retries", "2",
                "-oX", xml_path,
            ]
        elif scan_type == "full_scan":
            # Combined: all ports + services + vuln scripts
            cmd += [
                "-sS", "-sV",
                "-p", ports,
                "--open",
                "--script", (
                    "vuln,"
                    "http-enum,"
                    "http-headers,"
                    "http-methods,"
                    "http-title,"
                    "http-server-header,"
                    "ssl-cert,"
                    "ssl-enum-ciphers"
                ),
                "--script-timeout", "30s",
                "-T4",
                "--max-retries", "2",
                "-oX", xml_path,
            ]
        else:
            result.error = f"Unknown scan_type: {scan_type}"
            return result

        cmd.append(host)
        result.command = " ".join(cmd)

        if verbose:
            print(f"  [nmap] Running: {result.command}")

        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        result.raw_output = proc.stdout + proc.stderr

        # Parse XML output
        if os.path.exists(xml_path):
            result.xml_output = Path(xml_path).read_text(encoding="utf-8",
                                                          errors="replace")
            parsed = _parse_nmap_xml(result.xml_output)
            result.open_ports = parsed["ports"]
            result.services = parsed["services"]
            result.os_detection = parsed["os"]

            # Extract vulnerabilities from script results
            for script in parsed["scripts"]:
                sid = script["script"]
                out = script["output"]
                port = script["port"]
                # vuln scripts usually contain VULNERABLE or CVE
                if ("VULNERABLE" in out.upper() or "CVE-" in out.upper()
                        or sid.startswith("http-vuln")
                        or sid == "vulners"):
                    result.vulnerabilities.append(
                        f"[{port}] {sid}: {out[:200]}"
                    )
                elif sid in ("http-enum", "http-headers", "http-title",
                             "http-methods", "http-server-header",
                             "http-robots.txt"):
                    # Informational, still useful
                    result.services.append(f"[{port}] {sid}: {out[:150]}")

        if proc.returncode != 0 and not result.open_ports:
            result.error = f"nmap exit code {proc.returncode}"

        if verbose:
            print(f"  [nmap] Open ports: {len(result.open_ports)}")
            for p in result.open_ports[:15]:
                print(f"    {p}")
            if result.vulnerabilities:
                print(f"  [nmap] Vulnerabilities: {len(result.vulnerabilities)}")
                for v in result.vulnerabilities:
                    print(f"    ⚠ {v[:120]}")

    except subprocess.TimeoutExpired:
        result.error = f"nmap timed out after {timeout}s"
    except FileNotFoundError:
        result.error = "nmap binary not found"
    except Exception as e:
        result.error = f"nmap error: {str(e)[:200]}"
    finally:
        if os.path.exists(xml_path):
            os.unlink(xml_path)

    return result


# ---------------------------------------------------------------------------
# GitHub wordlist download
# ---------------------------------------------------------------------------

def download_wordlists(dest_dir: Optional[Path] = None,
                       max_lists: int = 6,
                       verbose: bool = False) -> tuple[list[str], list[str]]:
    """Download file-index / crawling wordlists from GitHub.

    Returns ``(downloaded_files, all_paths)`` where *all_paths* is the
    deduplicated union of every line from every downloaded wordlist.
    """
    if requests is None:
        return [], []

    if dest_dir is None:
        dest_dir = Path(tempfile.mkdtemp(prefix="hicloud_wl_"))
    dest_dir.mkdir(parents=True, exist_ok=True)

    urls = GITHUB_WORDLISTS["download_urls"][:max_lists]
    downloaded: list[str] = []
    all_paths: list[str] = []
    seen: set[str] = set()

    session = _get_session()

    for url in urls:
        fname = url.rstrip("/").rsplit("/", 1)[-1]
        dest = dest_dir / fname
        if verbose:
            print(f"  [↓] Downloading {fname} …")
        try:
            resp = session.get(url, timeout=30, verify=False)
            if resp.status_code == 200 and len(resp.content) > 50:
                dest.write_bytes(resp.content)
                downloaded.append(str(dest))
                # Parse lines into paths
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Normalise: ensure leading slash
                    if not line.startswith("/"):
                        line = "/" + line
                    # Skip very long lines, binary junk, comments
                    if len(line) > 200:
                        continue
                    if line not in seen:
                        seen.add(line)
                        all_paths.append(line)
                if verbose:
                    print(f"         {len(resp.content):,} bytes → {dest}")
            else:
                if verbose:
                    print(f"         HTTP {resp.status_code} — skipped")
        except Exception as e:
            if verbose:
                print(f"         Error: {e}")

    if verbose:
        print(f"  [✓] {len(downloaded)} wordlists downloaded, "
              f"{len(all_paths)} unique paths loaded")

    return downloaded, all_paths


def load_wordlist_paths(wordlist_files: list[str]) -> list[str]:
    """Load paths from previously downloaded wordlist files."""
    paths: list[str] = []
    seen: set[str] = set()
    for fpath in wordlist_files:
        try:
            text = Path(fpath).read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if not line.startswith("/"):
                    line = "/" + line
                if len(line) > 200:
                    continue
                if line not in seen:
                    seen.add(line)
                    paths.append(line)
        except OSError:
            continue
    return paths


# ---------------------------------------------------------------------------
# HTTP probing
# ---------------------------------------------------------------------------

def _get_session() -> "requests.Session":
    """Create a requests session with retry logic."""
    if requests is None:
        raise ImportError("requests library is required")
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        max_retries=urllib3.util.retry.Retry(
            total=2, backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
        )
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def http_probe(url: str, method: str = "GET",
               user_agent: str = "HuaweiHomeGateway",
               timeout: float = 10.0,
               data: Optional[str] = None,
               session: Optional["requests.Session"] = None) -> HttpProbeResult:
    """Probe a URL with a specific HTTP method and User-Agent."""
    if requests is None:
        return HttpProbeResult(url=url, method=method, user_agent=user_agent,
                               error="requests library not installed")

    result = HttpProbeResult(url=url, method=method, user_agent=user_agent)
    sess = session or _get_session()

    headers = {
        "User-Agent": user_agent,
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
    }

    try:
        t0 = time.monotonic()
        if method.upper() == "GET":
            resp = sess.get(url, headers=headers, timeout=timeout,
                            verify=False, allow_redirects=False)
        elif method.upper() == "HEAD":
            resp = sess.head(url, headers=headers, timeout=timeout,
                             verify=False, allow_redirects=False)
        elif method.upper() == "POST":
            resp = sess.post(url, headers=headers, timeout=timeout,
                             verify=False, allow_redirects=False,
                             data=data or "")
        elif method.upper() == "OPTIONS":
            resp = sess.options(url, headers=headers, timeout=timeout,
                                verify=False, allow_redirects=False)
        elif method.upper() == "PUT":
            resp = sess.put(url, headers=headers, timeout=timeout,
                            verify=False, allow_redirects=False,
                            data=data or "")
        else:
            result.error = f"Unsupported method: {method}"
            return result

        elapsed = (time.monotonic() - t0) * 1000
        result.latency_ms = elapsed
        result.status_code = resp.status_code
        result.server = resp.headers.get("Server", "")
        result.content_type = resp.headers.get("Content-Type", "")
        cl = resp.headers.get("Content-Length", "")
        result.content_length = int(cl) if cl.isdigit() else len(resp.content)
        result.redirect = resp.headers.get("Location", "")
        result.headers = dict(resp.headers)
        # Preview body for non-binary content
        ct = result.content_type.lower()
        if any(t in ct for t in ("text", "html", "xml", "json", "javascript")):
            result.body_preview = resp.text[:500]
        elif result.content_length > 0:
            result.body_preview = f"[binary data: {result.content_length} bytes]"

    except requests.exceptions.ConnectionError as e:
        result.error = f"Connection error: {str(e)[:100]}"
    except requests.exceptions.Timeout:
        result.error = "Timeout"
    except requests.exceptions.RequestException as e:
        result.error = f"Request error: {str(e)[:100]}"
    except Exception as e:
        result.error = f"Error: {str(e)[:100]}"

    return result


def probe_url_multi_method(url: str, user_agents: list[str] | None = None,
                           methods: list[str] | None = None,
                           session: Optional["requests.Session"] = None,
                           verbose: bool = False) -> list[HttpProbeResult]:
    """Probe a URL with multiple methods and User-Agents."""
    if user_agents is None:
        user_agents = USER_AGENTS[:3]  # Top 3 most relevant
    if methods is None:
        methods = ["GET", "HEAD", "OPTIONS"]

    results = []
    for method in methods:
        for ua in user_agents:
            r = http_probe(url, method=method, user_agent=ua, session=session)
            results.append(r)
            if verbose and r.status_code:
                print(f"  [{r.status_code}] {method:7s} {url}  UA={ua[:30]}")
    return results


# ---------------------------------------------------------------------------
# Path / directory discovery
# ---------------------------------------------------------------------------

def discover_paths(base_url: str, paths: list[str],
                   session: Optional["requests.Session"] = None,
                   verbose: bool = False) -> list[HttpProbeResult]:
    """Probe multiple paths on a base URL."""
    results = []
    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    if verbose:
        print(f"\n[*] Probing {len(paths)} paths on {base}...")

    for path in paths:
        url = base + path
        r = http_probe(url, session=session)
        results.append(r)
        if verbose and r.status_code and r.status_code < 400:
            print(f"  [{r.status_code}] {url}  ({r.content_type})")

    return results


def discover_index_files(base_url: str,
                         filenames: list[str] | None = None,
                         session: Optional["requests.Session"] = None,
                         verbose: bool = False) -> list[HttpProbeResult]:
    """Search for index/directory listing files at a URL."""
    if filenames is None:
        filenames = INDEX_FILENAMES

    results = []
    base = base_url.rstrip("/") + "/"

    if verbose:
        print(f"\n[*] Searching for {len(filenames)} index files at {base}...")

    for fn in filenames:
        url = base + fn
        r = http_probe(url, session=session)
        results.append(r)
        if verbose and r.status_code and r.status_code < 400:
            print(f"  [FOUND] [{r.status_code}] {url}")

    return results


# ---------------------------------------------------------------------------
# TDS path enumeration
# ---------------------------------------------------------------------------

def enumerate_tds_paths(host: str, port: int = 8180,
                        scheme: str = "http",
                        session: Optional["requests.Session"] = None,
                        verbose: bool = False,
                        fast: bool = False) -> list[HttpProbeResult]:
    """Enumerate Huawei TDS path patterns to find firmware files."""
    results = []
    base = f"{scheme}://{host}:{port}"

    products = TDS_PRODUCTS[:3] if fast else TDS_PRODUCTS
    series = TDS_SERIES[:6] if fast else TDS_SERIES
    groups = TDS_GROUPS[:3] if fast else TDS_GROUPS
    versions = TDS_VERSIONS[:5] if fast else TDS_VERSIONS

    if verbose:
        total = len(products) * len(series) * len(groups)
        print(f"\n[*] Enumerating TDS paths ({total} combinations)...")

    for prod in products:
        for ser in series:
            for grp in groups:
                path = f"/TDS/data/files/{prod}/{ser}/{grp}/g0/"
                url = base + path
                r = http_probe(url, session=session, timeout=5.0)
                results.append(r)
                if r.status_code and r.status_code < 400:
                    if verbose:
                        print(f"  [HIT] [{r.status_code}] {url}")
                    # If we got a hit, try versions under it
                    for ver in versions:
                        for ft in TDS_FILES[:2]:
                            for typ in TDS_TYPES[:2]:
                                vurl = f"{url}{ver}/{ft}/{typ}/"
                                vr = http_probe(vurl, session=session, timeout=5.0)
                                results.append(vr)
                                if vr.status_code and vr.status_code < 400 and verbose:
                                    print(f"    [HIT] [{vr.status_code}] {vurl}")

    return results


# ---------------------------------------------------------------------------
# Firmware search
# ---------------------------------------------------------------------------


def _generate_firmware_filenames() -> list[str]:
    """Dynamically generate candidate firmware filenames from naming patterns.

    No hardcoded filenames — builds candidates by combining model names,
    version patterns, and common firmware extensions.
    """
    models = ["HG8145V5", "HG8145V5-12", "EG8145V5"]
    extensions = [".bin", ".hwnp", ".bin.gz", ".bin.zip", ".tar.gz", ".img"]
    generic = ["firmware", "upgrade", "update", "image", "flash"]

    filenames: list[str] = []

    # model + extension
    for model in models:
        for ext in extensions:
            filenames.append(f"{model}{ext}")

    # generic + extension
    for g in generic:
        for ext in extensions[:2]:
            filenames.append(f"{g}{ext}")

    return filenames

def search_firmware_files(base_url: str,
                          firmware_files: list[str] | None = None,
                          paths: list[str] | None = None,
                          session: Optional["requests.Session"] = None,
                          verbose: bool = False) -> list[FirmwareCandidate]:
    """Search for specific firmware files on the server.

    When *firmware_files* is empty or ``None``, dynamically generates
    candidate filenames from common firmware naming conventions.
    """
    if not firmware_files:
        # Build filenames dynamically from common patterns
        firmware_files = _generate_firmware_filenames()
    if paths is None:
        paths = [""]  # just the base URL

    candidates = []
    base = base_url.rstrip("/")

    if verbose:
        total = len(firmware_files) * len(paths)
        print(f"\n[*] Searching for {len(firmware_files)} firmware files"
              f" × {len(paths)} paths ({total} requests)...")

    for path in paths:
        for fn in firmware_files:
            url = f"{base}{path}/{fn}" if path else f"{base}/{fn}"
            r = http_probe(url, method="HEAD", session=session, timeout=10.0)

            candidate = FirmwareCandidate(
                url=url,
                filename=fn,
                status_code=r.status_code,
                content_type=r.content_type,
                content_length=r.content_length,
                server=r.server,
            )

            # Check if this looks like a downloadable firmware file
            if r.status_code == 200:
                ct = r.content_type.lower()
                is_binary_ct = (
                    "octet-stream" in ct or
                    "binary" in ct or
                    "application/x-" in ct
                )
                is_text_ct = (
                    "text/html" in ct or
                    "text/plain" in ct or
                    "text/xml" in ct or
                    "application/json" in ct
                )
                # Firmware files should be >1MB binary data
                if is_binary_ct and r.content_length > 0:
                    candidate.is_downloadable = True
                elif r.content_length > 1_000_000 and not is_text_ct:
                    candidate.is_downloadable = True
                elif (fn.endswith((".bin", ".hwnp", ".gz", ".zip"))
                      and r.content_length > 1_000_000
                      and not is_text_ct):
                    candidate.is_downloadable = True

            candidates.append(candidate)

            if verbose:
                if candidate.is_downloadable:
                    size = r.content_length
                    print(f"  [FIRMWARE FOUND] {fn}  ({size:,} bytes)  {url}")
                elif r.status_code and r.status_code < 400:
                    print(f"  [{r.status_code}] {fn}  {url}")

    return candidates


def download_firmware(candidate: FirmwareCandidate,
                      download_dir: Path,
                      session: Optional["requests.Session"] = None,
                      verbose: bool = False) -> bool:
    """Download a firmware file."""
    if requests is None:
        return False

    sess = session or _get_session()
    download_dir.mkdir(parents=True, exist_ok=True)
    dest = download_dir / candidate.filename

    if verbose:
        print(f"\n[*] Downloading {candidate.filename} from {candidate.url}...")

    try:
        resp = sess.get(
            candidate.url,
            headers={"User-Agent": "HuaweiHomeGateway"},
            timeout=300,
            verify=False,
            stream=True,
        )
        if resp.status_code != 200:
            if verbose:
                print(f"  [!] HTTP {resp.status_code}")
            return False

        sha256 = hashlib.sha256()
        total = 0
        with open(dest, "wb") as f:
            for chunk in resp.iter_content(chunk_size=65536):
                f.write(chunk)
                sha256.update(chunk)
                total += len(chunk)

        candidate.sha256 = sha256.hexdigest()
        candidate.download_path = str(dest)
        candidate.content_length = total

        if verbose:
            print(f"  [✓] Downloaded {total:,} bytes → {dest}")
            print(f"  [✓] SHA-256: {candidate.sha256}")
        return True

    except Exception as e:
        if verbose:
            print(f"  [!] Download failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Full scan orchestration
# ---------------------------------------------------------------------------

def run_scan(
    scan_ports_flag: bool = False,
    nmap_scan: bool = False,
    use_wordlists: bool = False,
    fast: bool = False,
    download_dir: Optional[Path] = None,
    verbose: bool = True,
) -> ScanReport:
    """Run the full HiCloud firmware server scan."""
    report = ScanReport()
    report.timestamp = datetime.now(timezone.utc).isoformat()

    if requests is None:
        print("[!] requests library not installed. Install with: pip install requests")
        report.summary = "Error: requests library not installed"
        return report

    session = _get_session()

    # 1. DNS Resolution
    print("[*] Phase 1: DNS Resolution")
    print("-" * 40)
    for host in HICLOUD_HOSTS[:5]:  # Top hosts
        ips = resolve_host(host)
        if ips:
            print(f"  {host}: {', '.join(ips)}")
            report.resolved_ips.extend(ips)
    report.resolved_ips = list(set(report.resolved_ips))
    print()

    # 2. Nmap full port scan + vulnerability detection (if requested)
    if nmap_scan:
        print("[*] Phase 2: Nmap Port Scan (all ports)")
        print("-" * 40)
        if _nmap_available():
            port_range = "1-10000" if fast else "-"
            nr = run_nmap_scan(TARGET_HOST, scan_type="port_scan",
                               ports=port_range, verbose=verbose)
            report.nmap_results.append(nr)

            # Vulnerability scan on discovered open ports
            if nr.open_ports:
                open_str = ",".join(p.split("/")[0] for p in nr.open_ports)
                print(f"\n  [*] Running vulnerability scan on {open_str}...")
                vr = run_nmap_scan(TARGET_HOST, scan_type="vuln_scan",
                                   ports=open_str, verbose=verbose)
                report.nmap_results.append(vr)
            else:
                # Still run vuln scan on common ports
                print("\n  [*] Running vulnerability scan on common ports...")
                common = "80,443,8080,8180,8443,7547"
                vr = run_nmap_scan(TARGET_HOST, scan_type="vuln_scan",
                                   ports=common, verbose=verbose)
                report.nmap_results.append(vr)
        else:
            print("  [!] nmap not installed — skipping")
        print()
    elif scan_ports_flag:
        # Fallback: Python port scan
        print("[*] Phase 2: Port Scanning (Python)")
        print("-" * 40)
        tcp_ports = DEFAULT_TCP_PORTS[:20] if fast else DEFAULT_TCP_PORTS
        udp_ports = DEFAULT_UDP_PORTS[:5] if fast else DEFAULT_UDP_PORTS
        tcp_results, udp_results = scan_ports(
            TARGET_HOST, tcp_ports, udp_ports, verbose=verbose
        )
        report.tcp_ports = tcp_results
        report.udp_ports = udp_results
        open_tcp = [p for p in tcp_results if p.state == "open"]
        print(f"\n  Open TCP ports: {len(open_tcp)}")
        print()

    # 3. Download GitHub wordlists (always — no hardcoded paths)
    wordlist_paths: list[str] = []
    print("[*] Phase 3: Downloading GitHub Wordlists")
    print("-" * 40)
    wl_dir = Path(tempfile.mkdtemp(prefix="hicloud_wl_"))
    downloaded, wordlist_paths = download_wordlists(
        dest_dir=wl_dir, verbose=verbose,
    )
    report.wordlists_downloaded = downloaded
    if not wordlist_paths:
        print("  [!] No wordlists downloaded — scan will be limited")
    print()

    # 4. HTTP probing of the base URL with multiple methods/UAs
    print("[*] Phase 4: HTTP Multi-Method Probing")
    print("-" * 40)
    methods = ["GET", "HEAD", "OPTIONS", "POST"]
    uas = USER_AGENTS[:4] if fast else USER_AGENTS

    # Probe the base URL
    probes = probe_url_multi_method(
        BASE_URL, user_agents=uas, methods=methods,
        session=session, verbose=verbose,
    )
    report.http_probes.extend(probes)

    # Also probe base URL on different ports
    for port in [80, 443, 8080, 8443]:
        for scheme in ["http", "https"]:
            alt_url = f"{scheme}://{TARGET_HOST}:{port}/TDS/data/files/p9/s115/G345/g0/v10149/f1/full/"
            r = http_probe(alt_url, session=session, timeout=5.0)
            report.http_probes.append(r)
            if verbose and r.status_code:
                print(f"  [{r.status_code}] {alt_url}")
    print()

    # 5. Path discovery (using downloaded wordlists only — no hardcoded paths)
    print("[*] Phase 5: Path Discovery (from wordlists)")
    print("-" * 40)
    all_paths = list(wordlist_paths)
    limit = 200 if fast else 500
    if all_paths:
        all_paths = all_paths[:limit]
        print(f"  (Using {len(all_paths)} paths from downloaded wordlists)")
    else:
        print("  (No wordlist paths available — skipping)")
    path_results = discover_paths(
        f"http://{TARGET_HOST}:8180",
        all_paths, session=session, verbose=verbose,
    ) if all_paths else []
    report.path_discovery = path_results
    found_paths = [p for p in path_results if p.status_code and p.status_code < 400]
    print(f"\n  Paths with responses: {len(found_paths)}")
    print()

    # 6. Index file discovery (from wordlists only)
    print("[*] Phase 6: Index File Discovery (from wordlists)")
    print("-" * 40)
    # Build index filename list from wordlist entries that look like filenames
    wl_index_files = [
        p.lstrip("/") for p in wordlist_paths
        if "." in p and len(p) < 60 and "/" not in p.lstrip("/")
    ][:100]

    index_results = discover_index_files(
        BASE_URL, filenames=wl_index_files, session=session, verbose=verbose,
    ) if wl_index_files else []
    report.index_files = index_results
    # Also check root
    root_index = discover_index_files(
        f"http://{TARGET_HOST}:8180/",
        session=session, verbose=verbose,
    )
    report.index_files.extend(root_index)
    found_index = [p for p in report.index_files if p.status_code and p.status_code < 400]
    print(f"\n  Index files found: {len(found_index)}")
    print()

    # 7. TDS path enumeration (only if wordlists provided TDS-like paths)
    print("[*] Phase 7: TDS Path Enumeration (dynamic)")
    print("-" * 40)
    tds_results = enumerate_tds_paths(
        TARGET_HOST, session=session, verbose=verbose, fast=fast,
    ) if TDS_PRODUCTS else []
    report.tds_probes = tds_results
    found_tds = [p for p in tds_results if p.status_code and p.status_code < 400]
    if not TDS_PRODUCTS:
        print("  (No TDS patterns loaded — using wordlist paths only)")
    else:
        print(f"\n  TDS paths with responses: {len(found_tds)}")
    print()

    # 8. Firmware file search (using wordlist-discovered paths only)
    print("[*] Phase 8: HG8145V5 / HG8145V5-12 Firmware Search (dynamic)")
    print("-" * 40)
    search_bases = [BASE_URL.rstrip("/")]
    # Add any paths that returned non-404 responses
    for p in found_paths:
        url = p.url if hasattr(p, 'url') else p.get('url', '')
        if url:
            search_bases.append(url.rstrip("/"))
    search_bases = list(dict.fromkeys(search_bases))

    for base in search_bases:
        candidates = search_firmware_files(
            base, session=session, verbose=verbose,
        )
        report.firmware_candidates.extend(candidates)

    # 9. Download any found firmware
    downloadable = [f for f in report.firmware_candidates if f.is_downloadable]
    if downloadable and download_dir:
        print(f"\n[*] Phase 9: Downloading {len(downloadable)} firmware files")
        print("-" * 40)
        for fw in downloadable:
            download_firmware(fw, download_dir, session=session, verbose=verbose)

    # Build summary
    total_probes = (len(report.http_probes) + len(report.path_discovery) +
                    len(report.index_files) + len(report.tds_probes))
    ok_count = sum(1 for p in (report.http_probes + report.path_discovery +
                                report.index_files + report.tds_probes)
                   if (p.status_code if hasattr(p, 'status_code')
                       else p.get('status_code', 0)) in range(200, 400))

    nmap_info = ""
    if report.nmap_results:
        total_open = sum(len(n.open_ports) for n in report.nmap_results
                         if hasattr(n, 'open_ports'))
        total_vulns = sum(len(n.vulnerabilities) for n in report.nmap_results
                          if hasattr(n, 'vulnerabilities'))
        nmap_info = (f" Nmap found {total_open} open ports, "
                     f"{total_vulns} vulnerabilities.")

    wl_info = ""
    if report.wordlists_downloaded:
        wl_info = f" {len(report.wordlists_downloaded)} wordlists downloaded."

    report.summary = (
        f"Scan complete. {total_probes} HTTP probes sent, "
        f"{ok_count} responses with 2xx/3xx status. "
        f"{len(report.firmware_candidates)} firmware candidates checked, "
        f"{len(downloadable)} downloadable.{nmap_info}{wl_info}"
    )

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Huawei HiCloud Firmware Update Server Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python hicloud_scanner.py\n"
            "  python hicloud_scanner.py --scan-ports\n"
            "  python hicloud_scanner.py --nmap --wordlists\n"
            "  python hicloud_scanner.py --download-dir ./firmware\n"
            "  python hicloud_scanner.py --json results.json --fast\n"
        ),
    )
    parser.add_argument(
        "--scan-ports", action="store_true", default=False,
        help="Enable Python TCP/UDP port scanning (use --nmap instead for full scan)",
    )
    parser.add_argument(
        "--nmap", action="store_true", default=False,
        help="Use nmap for full port scanning + vulnerability detection (NSE scripts)",
    )
    parser.add_argument(
        "--wordlists", action="store_true", default=False,
        help="Download file-index wordlists from GitHub (SecLists, fuzzdb, fuzz.txt)",
    )
    parser.add_argument(
        "--fast", action="store_true", default=False,
        help="Fast mode: reduce path enumeration depth",
    )
    parser.add_argument(
        "--download-dir", type=Path, default=None,
        help="Directory to download discovered firmware files",
    )
    parser.add_argument(
        "--json", dest="json_output", default=None,
        help="Save full report as JSON",
    )
    parser.add_argument(
        "--quiet", action="store_true", default=False,
        help="Suppress verbose output",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    report = run_scan(
        scan_ports_flag=args.scan_ports,
        nmap_scan=args.nmap,
        use_wordlists=args.wordlists,
        fast=args.fast,
        download_dir=args.download_dir,
        verbose=not args.quiet,
    )

    report.print_summary()

    if args.json_output:
        path = report.save(Path(args.json_output))
        print(f"\nReport saved to: {path}")


if __name__ == "__main__":
    main()
