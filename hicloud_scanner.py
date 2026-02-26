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
import socket
import ssl
import struct
import sys
import time
import urllib.parse
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

# Base TDS path components to try
TDS_PRODUCTS = ["p9", "p3", "p1", "p2", "p5", "p10", "p11", "p15", "p20"]
TDS_SERIES = [
    "s115",   # HG8145V5
    "s116",   # HG8145V5 variant
    "s117",   # HG8145V5-12 ?
    "s118", "s119", "s120",
    "s100", "s101", "s102", "s103", "s104", "s105",
    "s110", "s111", "s112", "s113", "s114",
    "s121", "s122", "s123", "s124", "s125",
    "s130", "s140", "s150", "s200", "s210",
]
TDS_GROUPS = ["G345", "G346", "G347", "G100", "G200", "G300", "G400", "G500"]
TDS_VERSIONS = [
    "v10149", "v10150", "v10151", "v10152", "v10153",
    "v10100", "v10101", "v10110", "v10120", "v10130", "v10140",
    "v10200", "v10201", "v10210", "v10220", "v10250",
    "v10300", "v10340", "v10350", "v10368",
    "v20000", "v20100", "v20200", "v20212",
]
TDS_FILES = ["f1", "f2", "f3"]
TDS_TYPES = ["full", "inc", "diff"]

# ---------------------------------------------------------------------------
# Path dictionaries for directory brute-forcing
# ---------------------------------------------------------------------------
# Common firmware-related paths to probe on the server

COMMON_PATHS = [
    "/",
    "/TDS/",
    "/TDS/data/",
    "/TDS/data/files/",
    "/TDS/data/files/p9/",
    "/TDS/data/files/p9/s115/",
    "/TDS/data/files/p9/s115/G345/",
    "/TDS/data/files/p9/s115/G345/g0/",
    "/TDS/data/files/p9/s115/G345/g0/v10149/",
    "/TDS/data/files/p9/s115/G345/g0/v10149/f1/",
    "/TDS/data/files/p9/s115/G345/g0/v10149/f1/full/",
    # Alternative path structures
    "/firmware/",
    "/firmware/update/",
    "/firmware/download/",
    "/firmware/HG8145V5/",
    "/firmware/EG8145V5/",
    "/firmware/HG8145V5-12/",
    "/update/",
    "/upgrade/",
    "/download/",
    "/files/",
    "/data/",
    "/ont/",
    "/ont/firmware/",
    "/cpe/firmware/",
    "/images/",
    "/bin/",
    # REST API endpoints
    "/api/",
    "/api/firmware/",
    "/api/v1/firmware/",
    "/api/update/",
    "/api/download/",
    # Status/health endpoints
    "/status",
    "/health",
    "/version",
    "/info",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/",
    "/server-status",
    "/server-info",
]

# Common index/directory listing filenames to check
INDEX_FILENAMES = [
    "index.html",
    "index.htm",
    "index.php",
    "index.asp",
    "index.aspx",
    "index.jsp",
    "index.xml",
    "index.json",
    "index.txt",
    "default.html",
    "default.htm",
    "default.asp",
    "default.aspx",
    "filelist.xml",
    "filelist.txt",
    "files.xml",
    "files.json",
    "manifest.xml",
    "manifest.json",
    "update.xml",
    "update.json",
    "firmware.xml",
    "firmware.json",
    "changelog.xml",
    "changelog.txt",
    "version.xml",
    "version.txt",
    "version.json",
    "README",
    "README.txt",
    "ls.txt",
    "dir.txt",
    "listing.html",
    ".listing",
]

# Firmware filenames specifically for HG8145V5 and HG8145V5-12
HG8145V5_FIRMWARE_FILES = [
    # Standard naming conventions
    "HG8145V5.bin",
    "HG8145V5-12.bin",
    "EG8145V5.bin",
    "EG8145V5-V500R022C00SPC340B019.bin",
    "HG8145V5_V500R022C00SPC368.bin",
    "HG8145V5_V500R022C00SPC340B019.bin",
    "HG8145V5_V500R020C10SPC212.bin",
    "HG8145V5_V500R020C00SPC458B001.bin",
    "HG8145V5-12_V500R022C00SPC340.bin",
    "HG8145V5-12_V500R022C00SPC368.bin",
    "HG8145V5-12_V500R020C10SPC212.bin",
    "5611_HG8145V5V500R020C10SPC212.bin",
    # HWNP format variants
    "HG8145V5.hwnp",
    "HG8145V5-12.hwnp",
    "EG8145V5.hwnp",
    # Compressed variants
    "HG8145V5.bin.gz",
    "HG8145V5.bin.zip",
    "HG8145V5.tar.gz",
    "HG8145V5-12.bin.gz",
    # Generic names
    "firmware.bin",
    "upgrade.bin",
    "update.bin",
    "image.bin",
    "flash.bin",
    # Version-specific patterns
    "V500R022C00SPC340B019.bin",
    "V500R022C00SPC368.bin",
    "V500R020C10SPC212.bin",
    "V500R020C00SPC458B001.bin",
]

# GitHub wordlists commonly used for web directory fuzzing
GITHUB_WORDLISTS = {
    "description": "Well-known directory/file wordlists from GitHub security tools",
    "sources": [
        "https://github.com/danielmiessler/SecLists (Discovery/Web-Content)",
        "https://github.com/fuzzdb-project/fuzzdb (discovery/predictable-filepaths)",
        "https://github.com/Bo0oM/fuzz.txt",
        "https://github.com/six2dez/OneListForAll",
    ],
    # Curated subset of high-value paths from these wordlists
    "paths": [
        "/admin/", "/administrator/", "/backup/", "/config/",
        "/console/", "/dashboard/", "/debug/", "/deploy/",
        "/dev/", "/dist/", "/docs/", "/error/", "/export/",
        "/help/", "/home/", "/images/", "/img/", "/include/",
        "/internal/", "/log/", "/logs/", "/media/", "/misc/",
        "/modules/", "/monitor/", "/node/", "/old/", "/panel/",
        "/portal/", "/private/", "/public/", "/release/",
        "/releases/", "/repo/", "/repository/", "/resource/",
        "/resources/", "/scripts/", "/service/", "/services/",
        "/share/", "/shared/", "/static/", "/storage/", "/store/",
        "/system/", "/temp/", "/test/", "/testing/", "/tmp/",
        "/tools/", "/upload/", "/uploads/", "/usr/", "/var/",
        "/vendor/", "/web/", "/webapps/", "/www/",
        # Huawei-specific patterns
        "/TDS/", "/TDP/", "/TDC/",
        "/HMS/", "/EMUI/", "/HiLink/",
        "/OTA/", "/FOTA/", "/HOTA/",
        "/hicloud/", "/appgallery/",
        "/updater/", "/upgrader/",
        "/ontupdate/", "/cpeupdate/",
        "/firmware/latest/", "/firmware/stable/",
        "/firmware/beta/", "/firmware/release/",
    ],
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

def search_firmware_files(base_url: str,
                          firmware_files: list[str] | None = None,
                          paths: list[str] | None = None,
                          session: Optional["requests.Session"] = None,
                          verbose: bool = False) -> list[FirmwareCandidate]:
    """Search for specific firmware files on the server."""
    if firmware_files is None:
        firmware_files = HG8145V5_FIRMWARE_FILES
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

    # 2. Port scanning (optional, slow)
    if scan_ports_flag:
        print("[*] Phase 2: Port Scanning")
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

    # 3. HTTP probing of the base URL with multiple methods/UAs
    print("[*] Phase 3: HTTP Multi-Method Probing")
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

    # 4. Path discovery
    print("[*] Phase 4: Path Discovery")
    print("-" * 40)
    all_paths = COMMON_PATHS + GITHUB_WORDLISTS["paths"]
    if fast:
        all_paths = COMMON_PATHS  # Skip wordlist paths in fast mode
    path_results = discover_paths(
        f"http://{TARGET_HOST}:8180",
        all_paths, session=session, verbose=verbose,
    )
    report.path_discovery = path_results
    found_paths = [p for p in path_results if p.status_code and p.status_code < 400]
    print(f"\n  Paths with responses: {len(found_paths)}")
    print()

    # 5. Index file discovery
    print("[*] Phase 5: Index File Discovery")
    print("-" * 40)
    index_results = discover_index_files(
        BASE_URL, session=session, verbose=verbose,
    )
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

    # 6. TDS path enumeration
    print("[*] Phase 6: TDS Path Enumeration")
    print("-" * 40)
    tds_results = enumerate_tds_paths(
        TARGET_HOST, session=session, verbose=verbose, fast=fast,
    )
    report.tds_probes = tds_results
    found_tds = [p for p in tds_results if p.status_code and p.status_code < 400]
    print(f"\n  TDS paths with responses: {len(found_tds)}")
    print()

    # 7. Firmware file search
    print("[*] Phase 7: HG8145V5 / HG8145V5-12 Firmware Search")
    print("-" * 40)
    # Search on the base URL and key TDS paths
    search_bases = [
        BASE_URL.rstrip("/"),
        f"http://{TARGET_HOST}:8180",
        f"http://{TARGET_HOST}:8180/TDS/data/files/p9/s115/G345/g0/v10149/f1/full",
        f"http://{TARGET_HOST}:8180/firmware",
        f"http://{TARGET_HOST}:8180/download",
    ]
    # Add any discovered paths that returned 200
    for p in found_paths:
        url = p.url if hasattr(p, 'url') else p.get('url', '')
        if url:
            search_bases.append(url.rstrip("/"))
    search_bases = list(dict.fromkeys(search_bases))  # deduplicate

    for base in search_bases:
        candidates = search_firmware_files(
            base, session=session, verbose=verbose,
        )
        report.firmware_candidates.extend(candidates)

    # 8. Download any found firmware
    downloadable = [f for f in report.firmware_candidates if f.is_downloadable]
    if downloadable and download_dir:
        print(f"\n[*] Phase 8: Downloading {len(downloadable)} firmware files")
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

    report.summary = (
        f"Scan complete. {total_probes} HTTP probes sent, "
        f"{ok_count} responses with 2xx/3xx status. "
        f"{len(report.firmware_candidates)} firmware candidates checked, "
        f"{len(downloadable)} downloadable."
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
            "  python hicloud_scanner.py --download-dir ./firmware\n"
            "  python hicloud_scanner.py --json results.json --fast\n"
        ),
    )
    parser.add_argument(
        "--scan-ports", action="store_true", default=False,
        help="Enable TCP/UDP port scanning (slow)",
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
