#!/usr/bin/env python3
"""
Huawei HiCloud Update Protocol Analysis
========================================

Reverse-engineered from:
- Live download of WS7200-20_11.0.5.5(C500)_main.bin from update.hicloud.com
- Capstone/radare2 disassembly of ONT_V100R002C00SPC253.exe updater
- String analysis and embedded shell script extraction

This module documents the complete HiCloud firmware update protocol
and provides functions to recreate the router's update-check and
download authentication flow.
"""

import base64
import hashlib
import json
import re
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


# ===================================================================
# HiCloud CDN infrastructure (from live captures)
# ===================================================================

HICLOUD_CDN = {
    "frontend": "update.hicloud.com",
    "backend": "Tencent Cloud CDN (qcloud)",
    "storage": "Huawei OBS (Object Storage Service)",
    "load_balancer": "ELB (Elastic Load Balancer)",
    "cdn_ips": [
        "43.152.2.78",
        "43.152.2.144",
        "43.152.2.154",
        "43.159.79.49",
        "43.175.104.21",
        "43.175.104.23",
        "43.175.104.29",
        "43.175.104.33",
        "43.175.104.46",
    ],
    "ports": {
        80: "HTTP (403 at root, 200 for valid firmware paths)",
        443: "HTTPS (400 Bad Request without TLS)",
        8180: "TDS service (404 — legacy, content purged)",
    },
}


# ===================================================================
# URL patterns discovered from live analysis
# ===================================================================

# Active download URL pattern (port 80, OBS backend)
HICLOUD_DOWNLOAD_URL_PATTERN = (
    "http://update.hicloud.com/download/data/"
    "pub_{bucket}/HWHOTA_hota_{product_id}_{series_id}/"
    "{hash_prefix}/{version_tag}/{auth_token}/{filename}"
)

# Legacy TDS URL pattern (port 8180, no longer serving content)
HICLOUD_TDS_URL_PATTERN = (
    "http://update.hicloud.com:8180/TDS/data/files/"
    "p{product}/s{series}/G{group}/g{subgroup}/"
    "v{version}/f{file_num}/{type}/"
)

# Known live download URLs (verified working as of analysis date)
VERIFIED_DOWNLOAD_URLS = [
    {
        "url": (
            "http://update.hicloud.com/download/data/pub_13/"
            "HWHOTA_hota_900_9/5e/v3/ISJ7Xk-tTpGg6prrAbWycw/"
            "WS7200-20_11.0.5.5(C500)_main.bin"
        ),
        "product": "WS7200-20 (Huawei WiFi Router)",
        "version": "11.0.5.5(C500)",
        "size_bytes": 27002944,
        "md5": "2391af62e6523f051ddc90e0dca1e926",
        "sha256": "ed8ebddedca1e22c225fb12bb4c1d8ac11d22f65ab575d309c439649eb644e3b",
        "server": "OBS",
        "status": "live",
        "last_modified": "2022-08-05T15:34:18Z",
    },
]


# ===================================================================
# URL component decoding (from binary analysis)
# ===================================================================

URL_COMPONENTS = {
    "pub_{N}": "Public OBS storage bucket number",
    "HWHOTA_hota": "Huawei Home Over-The-Air update type identifier",
    "product_id": "Product category (e.g. 900=router)",
    "series_id": "Product series within category",
    "hash_prefix": "First 2 chars of content hash (directory sharding)",
    "version_tag": "Version revision identifier (e.g. v3)",
    "auth_token": "Base64url-encoded download authentication token (16 bytes)",
    "filename": "Firmware binary filename with version",
}


# ===================================================================
# Firmware container format (from WS7200 binary analysis)
# ===================================================================

FIRMWARE_CONTAINER_FORMAT = {
    "name": "Huawei Encrypted Firmware Container",
    "magic": 0x1A0FF01A,
    "header_size": 32,
    "fields": {
        0x00: "Version (uint32, typically 1)",
        0x04: "Magic (uint32, 0x1A0FF01A)",
        0x08: "Type/Format (uint32, e.g. 0x00020001)",
        0x0C: "Header size (uint32, 32)",
        0x10: "Flags (uint32)",
        0x14: "Reserved (12 bytes, zeros)",
        0x20: "Padding (16 bytes, zeros)",
        0x30: "Encrypted payload begins (AES-256)",
    },
    "encryption": "AES-256 (entire payload after header is encrypted)",
    "note": "Cannot be decrypted without hardware-specific key from device",
}


# ===================================================================
# ONT router authentication protocol (from Capstone disassembly)
# ===================================================================

ONT_AUTH_PROTOCOL = {
    "description": (
        "Authentication flow extracted from ONT_V100R002C00SPC253.exe "
        "via Capstone x86 disassembly and string cross-reference analysis"
    ),
    "login_endpoint": "/login.cgi",
    "firmware_page": "/firmware.asp",
    "device_info_page": "/deviceinfo.asp",
    "http_version": "HTTP/1.0",
    "methods_supported": ["GET", "POST", "HEAD", "OPTIONS", "DELETE", "TRACE", "CONNECT"],
    "auth_headers": {
        "Authorization": "HTTP Digest or Basic authentication",
        "WWW-Authenticate": "Server challenge response",
    },
    "token_fields": {
        "onttoken": "ONT device authentication token",
        "x.X_HW_Token": "Huawei custom token (X_HW_Token TR-069 parameter)",
        "UploadToken": "Firmware upload authentication token",
    },
    "login_parameters": {
        "UserName": "Device username",
        "PassWord": "Device password",
        "Version": "Firmware version string",
        "LockTime": "Account lock timeout",
        "LoginTimes": "Login attempt counter",
        "LoginlockNum": "Max failed logins before lock",
        "Language": "UI language code",
        "Language_Id": "Language identifier",
    },
    "ssl_config": {
        "ca": "Huawei Root CA",
        "timestamp_ca": "Huawei Timestamp Certificate Authority",
        "code_signing_ca": "Huawei Code Signing Certificate Authority",
        "device_cert_cn": "rnd-ont.huawei.com",
        "tls_auth": "TLS Web Client Authentication + TLS Web Server Authentication",
    },
    "huawei_internal_endpoints": {
        "login_token": "http://login.huawei.com/login/rest/token",
        "person_api": "http://w3.huawei.com/ws/PersonServlet",
        "dts_portal": "https://dts-szv.clouddragon.huawei.com/DTSPortal/v1/",
    },
    "huawei_internal_auth_body": (
        '{{ "userName": "{username}", "password": "{password}", '
        '"authMethod": "password", '
        '"redirect": "http://w3.huawei.com" }}'
    ),
}


# ===================================================================
# Upgrade check protocol (from UpgradeCheck.xml and shell scripts)
# ===================================================================

UPGRADE_CHECK_XML_TEMPLATE = """\
<upgradecheck>
<HardVerCheck CheckEnable="0">
<IncludeList Enable="1"/>
<ExcludeList Enable="0"/>
</HardVerCheck>
<LswChipCheck CheckEnable="0">
<IncludeList Enable="1"/>
<ExcludeList Enable="0"/>
</LswChipCheck>
<WifiChipCheck CheckEnable="0">
<IncludeList Enable="1"/>
<ExcludeList Enable="0"/>
</WifiChipCheck>
<VoiceChipCheck CheckEnable="0">
<IncludeList Enable="1"/>
<ExcludeList Enable="0"/>
</VoiceChipCheck>
<UsbChipCheck CheckEnable="0">
<IncludeList Enable="1"/>
<ExcludeList Enable="0"/>
</UsbChipCheck>
<OpticalCheck CheckEnable="0">
<IncludeList Enable="1"/>
<ExcludeList Enable="0"/>
</OpticalCheck>
<OtherChipCheck CheckEnable="0">
<IncludeList Enable="1"/>
<ExcludeList Enable="0"/>
</OtherChipCheck>
<ProductCheck CheckEnable="0">
<IncludeList Enable="1"/>
<ExcludeList Enable="0"/>
</ProductCheck>
<ProgramCheck CheckEnable="0">
<IncludeList Enable="1"/>
<ExcludeList Enable="0"/>
</ProgramCheck>
<CfgCheck CheckEnable="0">
<IncludeList Enable="1"/>
<ExcludeList Enable="0"/>
</CfgCheck>
</upgradecheck>"""

UPGRADE_CHECK_HASHES = {
    "UpgradeCheck.xml": "6856f3f8fab4b2629a420a46568161ea38ab0cfd8c449a27d7ed0c4aa745c9c2",
    "Updateflag": "28312e346b76a3f91e8283519baab5f103d79547dedff5fb7ccc0dc3c5119bbe",
}

UPGRADE_SCRIPT_VARIABLES = {
    "var_upgrade_log": "/mnt/jffs2/upgrade_script_log.txt",
    "var_jffs2_current_ctree_file": "/mnt/jffs2/hw_ctree.xml",
    "var_current_ctree_bak_file": "/var/hw_ctree_equipbak.xml",
    "var_default_ctree_path": "/mnt/jffs2/hw_default_ctree.xml",
    "var_jffs2_boardinfo_file": "/mnt/jffs2/hw_boardinfo",
    "var_file_equipfile": "/mnt/jffs2/equipment.tar.gz",
    "var_pack_temp_dir": "/bin/",
}

UPGRADE_SCRIPT_FUNCTIONS = {
    "HW_Script_CreateLogFile": "Creates upgrade log at /mnt/jffs2/upgrade_script_log.txt",
    "HW_Script_Encrypt": "Encrypts config XML: gzip → aescrypt2 (mode 0 = encrypt)",
    "HW_Script_RecordInfo_5115": "Records board info (MachineItem, ConfigWord) to log",
    "HW_Script_SetCurrent_8120": "Sets VoIP current for HG8120C product type",
    "HW_Script_DealWithResetKey": "Handles factory reset button press",
    "HW_Script_DealWithDBKey": "Handles debug button press (short press)",
}

# WARNING: This key is extracted from publicly available firmware for
# research/analysis purposes only.  It must NOT be used in production systems.
_ANALYSIS_AES_KEY = "Df7!ui%s9(lmV1L8"

UPGRADE_ENCRYPTION_FLOW = {
    "encrypt": "gzip -f {file} → mv {file}.gz {file} → aescrypt2 0 {file} {file}_tmp",
    "decrypt": "aescrypt2 1 {file} {file}_tmp → mv {file} {file}.gz → gunzip -f {file}.gz",
    "aescrypt2_modes": {
        0: "Encrypt (AES-128-CBC)",
        1: "Decrypt",
    },
    "key": _ANALYSIS_AES_KEY,
    "key_source": "SPEC_OS_AES_CBC_APP_STR in spec_default.cfg",
}


# ===================================================================
# HTTP request/response format (from disassembly)
# ===================================================================

HTTP_REQUEST_FORMAT = {
    "template": "{method} {path} HTTP/1.0",
    "headers": {
        "Content-Type": ["application/octet-stream", "text/plain"],
        "Accept-Encoding": "gzip,deflate,sdch",
        "Cache-Control": "max-age=0",
        "Connection": "keep-alive",
        "User-Agent": "HuaweiHomeGateway",
    },
    "login_request": {
        "method": "POST",
        "path": "/login.cgi",
        "params": "UserName={user}&PassWord={pass}&x.X_HW_Token={token}",
    },
    "firmware_check": {
        "method": "GET",
        "path": "/firmware.asp",
    },
}


# ===================================================================
# CDN server response headers (from live capture)
# ===================================================================

CDN_RESPONSE_HEADERS = {
    "Server": "OBS (Huawei Object Storage Service)",
    "Content-Type": "application/octet-stream",
    "Accept-Ranges": "bytes",
    "ETag": "MD5 hash of file content",
    "X-NWS-LOG-UUID": "CDN request tracking ID",
    "cdnsip": "CDN edge server IP",
    "dl-from": "qcloud (Tencent Cloud CDN backend)",
    "X-Cache-Lookup": "Cache Hit / Cache Miss",
    "x-reserved": "amazon, aws and amazon web services are trademarks...",
    "x-amz-request-id": "S3-compatible request ID (OBS uses S3 API)",
    "x-amz-id-2": "S3-compatible secondary ID",
}


# ===================================================================
# Functions to recreate the update protocol
# ===================================================================

def decode_download_url(url: str) -> dict:
    """Parse and decode a HiCloud firmware download URL into components."""
    result = {"url": url, "components": {}}

    parsed = urllib.parse.urlparse(url)
    result["host"] = parsed.hostname
    result["port"] = parsed.port or 80
    result["path"] = parsed.path

    parts = parsed.path.strip("/").split("/")

    if len(parts) >= 7 and parts[0] == "download":
        result["url_type"] = "OBS download"
        result["components"]["bucket"] = parts[2]  # pub_13
        result["components"]["update_type"] = parts[3]  # HWHOTA_hota_900_9
        result["components"]["hash_prefix"] = parts[4]  # 5e
        result["components"]["version_tag"] = parts[5]  # v3
        result["components"]["auth_token_b64"] = parts[6]  # ISJ7Xk-tTpGg6prrAbWycw
        result["components"]["filename"] = "/".join(parts[7:])

        # Decode the auth token
        token_b64 = parts[6]
        padding = 4 - len(token_b64) % 4
        if padding != 4:
            token_b64 += "=" * padding
        token_b64_std = token_b64.replace("-", "+").replace("_", "/")
        try:
            token_bytes = base64.b64decode(token_b64_std)
            result["components"]["auth_token_hex"] = token_bytes.hex()
            result["components"]["auth_token_length"] = len(token_bytes)
        except Exception:
            pass

        # Parse product info from HWHOTA identifier
        hota_parts = parts[3].split("_")
        if len(hota_parts) >= 4:
            result["components"]["product_category"] = hota_parts[2]
            result["components"]["product_series"] = hota_parts[3]

    elif len(parts) >= 8 and parts[0] == "TDS":
        result["url_type"] = "TDS (legacy)"
        result["components"]["product"] = parts[3]   # p9
        result["components"]["series"] = parts[4]    # s92
        result["components"]["group"] = parts[5]     # G247
        result["components"]["subgroup"] = parts[6]  # g0
        result["components"]["version"] = parts[7]   # v90201
        if len(parts) > 8:
            result["components"]["file_num"] = parts[8]
        if len(parts) > 9:
            result["components"]["type"] = parts[9]

    return result


def parse_firmware_header(data: bytes) -> dict:
    """Parse the header of a Huawei encrypted firmware container."""
    import struct

    if len(data) < 32:
        return {"error": "Data too short for header"}

    result = {
        "format": "Unknown",
        "header_size": 0,
        "encrypted": False,
    }

    magic = struct.unpack("<I", data[4:8])[0]

    if magic == 0x1A0FF01A:
        result["format"] = "Huawei Encrypted Firmware Container"
        result["magic"] = f"0x{magic:08X}"
        result["version"] = struct.unpack("<I", data[0:4])[0]
        result["type"] = f"0x{struct.unpack('<I', data[8:12])[0]:08X}"
        result["header_size"] = struct.unpack("<I", data[12:16])[0]
        result["flags"] = f"0x{struct.unpack('<I', data[16:20])[0]:08X}"
        result["encrypted"] = True
        result["payload_offset"] = 0x30
        result["payload_size"] = len(data) - 0x30
    elif data[:4] == b"HWNP":
        result["format"] = "HWNP (Huawei Network Product)"
        result["magic"] = "HWNP"
        result["encrypted"] = False
    elif data[:2] == b"\x1f\x8b":
        result["format"] = "GZIP compressed"
        result["encrypted"] = False

    return result


def build_login_request(host: str, username: str, password: str,
                        token: str = "") -> dict:
    """Build an ONT router login HTTP request (from disassembly)."""
    return {
        "method": "POST",
        "url": f"http://{host}/login.cgi",
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "HuaweiHomeGateway",
            "Accept-Encoding": "gzip,deflate,sdch",
            "Cache-Control": "max-age=0",
            "Connection": "keep-alive",
        },
        "body": urllib.parse.urlencode({
            "UserName": username,
            "PassWord": password,
            "x.X_HW_Token": token,
        }),
    }


def build_firmware_check_request(host: str, cookie: str = "") -> dict:
    """Build firmware version check request (from disassembly)."""
    headers = {
        "User-Agent": "HuaweiHomeGateway",
        "Accept": "*/*",
        "Connection": "keep-alive",
    }
    if cookie:
        headers["Cookie"] = cookie
    return {
        "method": "GET",
        "url": f"http://{host}/firmware.asp",
        "headers": headers,
    }


def download_firmware_from_hicloud(url: str, dest_path: Path,
                                   verbose: bool = False) -> dict:
    """Download firmware from HiCloud CDN and verify integrity."""
    if requests is None:
        return {"error": "requests library not installed"}

    result = {
        "url": url,
        "status": "failed",
        "dest_path": str(dest_path),
    }

    session = requests.Session()
    headers = {"User-Agent": "HuaweiHomeGateway"}

    try:
        if verbose:
            print(f"[*] Downloading {url} ...")

        resp = session.get(url, headers=headers, timeout=300,
                           verify=False, stream=True)
        result["status_code"] = resp.status_code
        result["server"] = resp.headers.get("Server", "")
        result["etag"] = resp.headers.get("ETag", "").strip('"')
        result["content_type"] = resp.headers.get("Content-Type", "")
        result["cdnsip"] = resp.headers.get("cdnsip", "")
        result["dl_from"] = resp.headers.get("dl-from", "")
        result["cache"] = resp.headers.get("X-Cache-Lookup", "")

        if resp.status_code != 200:
            result["error"] = f"HTTP {resp.status_code}"
            return result

        dest_path.parent.mkdir(parents=True, exist_ok=True)
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        total = 0

        with open(dest_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=65536):
                f.write(chunk)
                md5.update(chunk)
                sha256.update(chunk)
                total += len(chunk)

        result["size_bytes"] = total
        result["md5"] = md5.hexdigest()
        result["sha256"] = sha256.hexdigest()
        result["status"] = "success"

        # Verify MD5 matches ETag (OBS uses MD5 as ETag)
        if result["etag"] and result["etag"] == result["md5"]:
            result["integrity"] = "verified (MD5 matches ETag)"
        elif result["etag"]:
            result["integrity"] = (
                f"mismatch (ETag={result['etag']}, MD5={result['md5']})"
            )
        else:
            result["integrity"] = "no ETag to verify against"

        # Parse firmware header
        with open(dest_path, "rb") as f:
            header_data = f.read(256)
        result["firmware_header"] = parse_firmware_header(header_data)

        if verbose:
            print(f"  [✓] Downloaded {total:,} bytes")
            print(f"  [✓] MD5:    {result['md5']}")
            print(f"  [✓] SHA256: {result['sha256']}")
            print(f"  [✓] Integrity: {result['integrity']}")
            print(f"  [✓] Format: {result['firmware_header']['format']}")

    except Exception as e:
        result["error"] = str(e)[:200]

    return result


# ===================================================================
# Firmware binary extraction and analysis
# ===================================================================

# Known firmware signatures for scanning
_FIRMWARE_SIGNATURES = {
    b"HWNP": "HWNP (Huawei Network Product)",
    b"hsqs": "SquashFS (Little-Endian)",
    b"sqsh": "SquashFS (Big-Endian)",
    b"\x1f\x8b\x08": "GZIP",
    b"\x27\x05\x19\x56": "uImage (U-Boot)",
    b"\x7fELF": "ELF binary",
    b"MZ": "PE/MZ executable",
    b"PK\x03\x04": "ZIP archive",
    b"UBI#": "UBI image",
    b"UBI!": "UBIFS superblock",
    b"\xd0\x0d\xfe\xed": "Device Tree Blob",
    b"-----BEGIN": "PEM certificate/key",
}


def scan_firmware_signatures(data: bytes, limit: int = 50) -> list[dict]:
    """Scan binary data for known firmware section signatures."""
    found = []
    for sig, name in _FIRMWARE_SIGNATURES.items():
        pos = 0
        while len(found) < limit:
            idx = data.find(sig, pos)
            if idx == -1:
                break
            found.append({
                "offset": idx,
                "offset_hex": f"0x{idx:08X}",
                "signature": name,
                "context_hex": data[idx:idx + 32].hex(),
            })
            pos = idx + 1
    found.sort(key=lambda x: x["offset"])
    return found[:limit]


def extract_hwnp_sections(data: bytes) -> list[dict]:
    """Find and parse HWNP firmware sections embedded in a binary."""
    sections = []
    pos = 0
    while True:
        idx = data.find(b"HWNP", pos)
        if idx == -1:
            break

        section: dict = {
            "offset": idx,
            "offset_hex": f"0x{idx:08X}",
            "magic": "HWNP",
        }

        # Parse fields after HWNP magic
        if idx + 64 <= len(data):
            header = data[idx:idx + 64]
            section["header_hex"] = header.hex()

            # Look for product list (ASCII pipe-separated values)
            text_start = data.find(b"|", idx + 4, idx + 200)
            if text_start > 0:
                # Walk back to start of product text
                ps = text_start
                while ps > idx + 4 and data[ps - 1:ps] not in (b"\x00",):
                    ps -= 1
                text_end = data.find(b"\x00", text_start, idx + 500)
                if text_end > text_start:
                    section["product_list"] = data[ps:text_end].decode(
                        "ascii", errors="replace"
                    )

        # Determine section size (until next HWNP or end of data)
        next_hwnp = data.find(b"HWNP", idx + 4)
        section_end = next_hwnp if next_hwnp != -1 else len(data)
        section["size"] = section_end - idx

        # Scan for embedded content
        sub_block = data[idx:section_end]
        for sig, name in _FIRMWARE_SIGNATURES.items():
            if sig == b"HWNP":
                continue
            sub_idx = sub_block.find(sig)
            if sub_idx > 0:
                section.setdefault("embedded", []).append({
                    "type": name,
                    "internal_offset": f"0x{sub_idx:X}",
                })

        sections.append(section)
        pos = idx + 4

    return sections


def extract_elf_info(data: bytes, offset: int = 0) -> dict:
    """Parse an ELF binary header at the given offset."""
    import struct as st

    elf = data[offset:]
    if len(elf) < 52 or elf[:4] != b"\x7fELF":
        return {"error": "Not a valid ELF"}

    info: dict = {"offset": offset, "offset_hex": f"0x{offset:08X}"}

    ei_class = elf[4]
    ei_data = elf[5]
    info["class"] = "32-bit" if ei_class == 1 else "64-bit"
    info["endian"] = "Little" if ei_data == 1 else "Big"

    if ei_data == 1:
        fmt = "<"
    else:
        fmt = ">"

    e_type = st.unpack(f"{fmt}H", elf[16:18])[0]
    e_machine = st.unpack(f"{fmt}H", elf[18:20])[0]

    type_names = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
    arch_names = {
        0x03: "x86", 0x08: "MIPS", 0x14: "PowerPC",
        0x28: "ARM", 0x3E: "x86_64", 0xB7: "AArch64",
    }
    info["type"] = type_names.get(e_type, f"0x{e_type:x}")
    info["architecture"] = arch_names.get(e_machine, f"0x{e_machine:x}")

    if ei_class == 1:  # 32-bit
        info["entry_point"] = f"0x{st.unpack(f'{fmt}I', elf[24:28])[0]:X}"
        e_shoff = st.unpack(f"{fmt}I", elf[32:36])[0]
        e_shentsize = st.unpack(f"{fmt}H", elf[46:48])[0]
        e_shnum = st.unpack(f"{fmt}H", elf[48:50])[0]
        info["estimated_size"] = e_shoff + (e_shentsize * e_shnum)

    # Extract key strings
    strings = re.findall(rb"[\x20-\x7e]{8,}", elf[:min(len(elf), 20000)])
    key_strings = []
    keywords = [
        "http", "update", "upgrade", "auth", "download", "firmware",
        "login", "pass", "key", "encrypt", "aes", "cert", "ssl",
        "token", "hw_", "huawei", "cwmp", "tr069", "lib",
    ]
    for s in strings:
        text = s.decode("ascii", errors="replace")
        if any(kw in text.lower() for kw in keywords):
            key_strings.append(text)
    info["key_strings"] = key_strings[:30]

    # Detect linked libraries
    libs = [s.decode("ascii") for s in strings
            if s.endswith(b".so") or b".so." in s]
    info["libraries"] = libs[:20]

    return info


def extract_shell_scripts(data: bytes) -> list[dict]:
    """Extract embedded shell scripts from a binary image."""
    scripts = []
    markers = [b"#!/bin/sh", b"#! /bin/sh"]
    seen_starts: set[int] = set()

    for marker in markers:
        pos = 0
        while True:
            idx = data.find(marker, pos)
            if idx == -1:
                break
            if idx in seen_starts:
                pos = idx + 1
                continue
            seen_starts.add(idx)

            # Walk forward to find end (null bytes or non-printable region)
            end = idx
            null_run = 0
            while end < len(data):
                b = data[end]
                if b == 0:
                    null_run += 1
                    if null_run >= 3:
                        end -= null_run
                        break
                else:
                    null_run = 0
                end += 1

            text = data[idx:end].replace(b"\x00", b"").decode(
                "utf-8", errors="replace"
            ).strip()

            if len(text) > 100:
                scripts.append({
                    "offset": idx,
                    "offset_hex": f"0x{idx:08X}",
                    "size": len(text),
                    "first_line": text.split("\n")[0][:80],
                    "content": text,
                    "has_aescrypt": "aescrypt2" in text,
                    "has_cfgtool": "cfgtool" in text,
                    "has_upgrade": "upgrade" in text.lower(),
                    "functions": re.findall(
                        r"(HW_\w+)\s*\(\)", text
                    ),
                })

            pos = idx + 1

    return scripts


def attempt_decryption(data: bytes, verbose: bool = False) -> dict:
    """Attempt to decrypt a Huawei encrypted firmware container.

    Tries multiple known keys and approaches. Returns information
    about decryption attempts and whether any succeeded.
    """
    import struct as st
    import math
    from collections import Counter

    result: dict = {
        "format_detected": False,
        "decrypted": False,
        "attempts": [],
        "analysis": "",
    }

    if len(data) < 48:
        result["analysis"] = "Data too short"
        return result

    magic = st.unpack("<I", data[4:8])[0]
    if magic != 0x1A0FF01A:
        result["analysis"] = f"Not a 0x1A0FF01A container (magic=0x{magic:08X})"
        return result

    result["format_detected"] = True
    header_size = st.unpack("<I", data[12:16])[0]
    payload = data[header_size + 16:]  # payload after header+padding

    # Entropy analysis
    def entropy_block(block: bytes) -> float:
        if not block:
            return 0.0
        c = Counter(block)
        length = len(block)
        return -sum(
            (cnt / length) * math.log2(cnt / length) for cnt in c.values()
        )

    payload_entropy = entropy_block(payload[:4096])
    result["payload_entropy"] = round(payload_entropy, 2)
    result["encryption_strength"] = (
        "strong" if payload_entropy > 7.9
        else "moderate" if payload_entropy > 7.5
        else "weak (possible plaintext)"
    )

    try:
        from Crypto.Cipher import AES
        has_crypto = True
    except ImportError:
        has_crypto = False
        result["analysis"] = (
            "pycryptodome not installed — install with: pip install pycryptodome"
        )
        return result

    # Known keys
    keys = [
        (_ANALYSIS_AES_KEY.encode(), "Config AES-128 key"),
        (hashlib.md5(_ANALYSIS_AES_KEY.encode()).digest(), "MD5(config key)"),
        (hashlib.sha256(_ANALYSIS_AES_KEY.encode()).digest()[:16], "SHA256(config key)[:16]"),
        (b"\x00" * 16, "Zero key"),
    ]

    ivs = [
        (b"\x00" * 16, "Zero IV"),
        (data[header_size:header_size + 16], "Header padding as IV"),
    ]

    for key, key_name in keys:
        for iv, iv_name in ivs:
            try:
                cipher = AES.new(key[:16], AES.MODE_CBC, iv)
                dec = cipher.decrypt(payload[:4096])
                ent = entropy_block(dec[:1024])
                attempt = {
                    "key": key_name,
                    "iv": iv_name,
                    "entropy": round(ent, 2),
                    "success": ent < 6.0,
                }

                # Check for known firmware signatures
                for sig, name in _FIRMWARE_SIGNATURES.items():
                    if dec[:len(sig)] == sig:
                        attempt["success"] = True
                        attempt["detected_format"] = name
                        break

                result["attempts"].append(attempt)

                if attempt["success"]:
                    result["decrypted"] = True
            except Exception:
                pass

    if not result["decrypted"]:
        result["analysis"] = (
            f"Payload entropy: {payload_entropy:.2f}/8.0 — "
            f"AES-256 encrypted with device-specific key. "
            f"The config AES key (Df7!ui%s9(lmV1L8) is only for "
            f"hw_ctree.xml config files, not firmware containers. "
            f"The firmware encryption key is derived from device hardware "
            f"via HW_CTOOL_GetKeyChipStr → HW_KMC_CfgGetKey."
        )

    return result


def analyze_firmware_binary(filepath: str,
                            verbose: bool = False) -> dict:
    """Perform comprehensive analysis of a firmware binary file.

    Combines header parsing, signature scanning, HWNP extraction,
    ELF analysis, script extraction, and decryption attempts.
    """
    result: dict = {"file": filepath}

    try:
        data = Path(filepath).read_bytes()
    except OSError as e:
        result["error"] = str(e)
        return result

    result["size_bytes"] = len(data)
    result["md5"] = hashlib.md5(data).hexdigest()
    result["sha256"] = hashlib.sha256(data).hexdigest()

    if verbose:
        print(f"[*] Analyzing {filepath} ({len(data):,} bytes)")

    # 1. Header
    result["header"] = parse_firmware_header(data)
    if verbose:
        print(f"  Format: {result['header'].get('format', 'unknown')}")

    # 2. Signature scan
    sigs = scan_firmware_signatures(data)
    result["signatures"] = sigs
    if verbose:
        print(f"  Signatures found: {len(sigs)}")

    # 3. HWNP sections
    hwnp = extract_hwnp_sections(data)
    result["hwnp_sections"] = hwnp
    if verbose:
        print(f"  HWNP sections: {len(hwnp)}")

    # 4. ELF binaries
    elf_offsets = [s["offset"] for s in sigs if "ELF" in s["signature"]]
    elfs = []
    for off in elf_offsets[:5]:
        info = extract_elf_info(data, off)
        elfs.append(info)
        if verbose and "architecture" in info:
            print(f"  ELF @ 0x{off:X}: {info['architecture']} "
                  f"{info.get('class', '')} {info.get('type', '')}")
    result["elf_binaries"] = elfs

    # 5. Shell scripts
    scripts = extract_shell_scripts(data)
    result["shell_scripts"] = [
        {k: v for k, v in s.items() if k != "content"}
        for s in scripts
    ]
    result["shell_scripts_full"] = scripts
    if verbose:
        print(f"  Shell scripts: {len(scripts)}")
        for s in scripts:
            print(f"    0x{s['offset']:X}: {s['first_line'][:60]} "
                  f"({s['size']:,} chars)")

    # 6. Decryption attempt (if encrypted container)
    if result["header"].get("encrypted"):
        dec = attempt_decryption(data, verbose=verbose)
        result["decryption"] = dec
        if verbose:
            print(f"  Decryption: {'SUCCESS' if dec['decrypted'] else 'FAILED'}")
            if dec.get("analysis"):
                print(f"    {dec['analysis'][:120]}")

    return result


# ===================================================================
# Report generation
# ===================================================================

@dataclass
class HiCloudAnalysisReport:
    """Complete HiCloud update protocol analysis report."""
    timestamp: str = ""
    cdn_infrastructure: dict = field(default_factory=lambda: dict(HICLOUD_CDN))
    download_url_pattern: str = HICLOUD_DOWNLOAD_URL_PATTERN
    tds_url_pattern: str = HICLOUD_TDS_URL_PATTERN
    firmware_container: dict = field(
        default_factory=lambda: dict(FIRMWARE_CONTAINER_FORMAT)
    )
    auth_protocol: dict = field(
        default_factory=lambda: dict(ONT_AUTH_PROTOCOL)
    )
    upgrade_check_xml: str = UPGRADE_CHECK_XML_TEMPLATE
    upgrade_script_functions: dict = field(
        default_factory=lambda: dict(UPGRADE_SCRIPT_FUNCTIONS)
    )
    encryption_flow: dict = field(
        default_factory=lambda: dict(UPGRADE_ENCRYPTION_FLOW)
    )
    cdn_headers: dict = field(
        default_factory=lambda: dict(CDN_RESPONSE_HEADERS)
    )
    verified_downloads: list = field(
        default_factory=lambda: list(VERIFIED_DOWNLOAD_URLS)
    )

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "cdn_infrastructure": self.cdn_infrastructure,
            "download_url_pattern": self.download_url_pattern,
            "tds_url_pattern": self.tds_url_pattern,
            "firmware_container_format": self.firmware_container,
            "ont_auth_protocol": self.auth_protocol,
            "upgrade_check_xml": self.upgrade_check_xml,
            "upgrade_script_functions": self.upgrade_script_functions,
            "encryption_flow": self.encryption_flow,
            "cdn_response_headers": self.cdn_headers,
            "verified_downloads": self.verified_downloads,
        }

    def save(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return path

    def print_summary(self) -> None:
        print("=" * 70)
        print("Huawei HiCloud Update Protocol Analysis")
        print("=" * 70)

        print("\n[CDN Infrastructure]")
        for k, v in self.cdn_infrastructure.items():
            if isinstance(v, list):
                print(f"  {k}: {', '.join(v[:5])}")
            elif isinstance(v, dict):
                for pk, pv in v.items():
                    print(f"  {k}/{pk}: {pv}")
            else:
                print(f"  {k}: {v}")

        print(f"\n[Download URL Pattern]")
        print(f"  {self.download_url_pattern}")

        print(f"\n[Authentication Protocol]")
        print(f"  Login: POST /login.cgi")
        print(f"  Params: UserName, PassWord, x.X_HW_Token")
        print(f"  Token: onttoken (device-generated)")
        print(f"  HTTP: {self.auth_protocol.get('http_version', 'HTTP/1.0')}")

        print(f"\n[Firmware Container]")
        print(f"  Magic: 0x1A0FF01A")
        print(f"  Encryption: AES-256 (payload only)")
        print(f"  Header: 32 bytes (unencrypted)")

        print(f"\n[Encryption Flow]")
        print(f"  Config encrypt: gzip → aescrypt2 (key=Df7!ui%s9(lmV1L8)")

        if self.verified_downloads:
            print(f"\n[Verified Downloads: {len(self.verified_downloads)}]")
            for dl in self.verified_downloads:
                print(f"  {dl['product']}: {dl['version']}")
                print(f"    Size: {dl['size_bytes']:,} bytes")
                print(f"    MD5:  {dl['md5']}")

        print("=" * 70)


def get_report() -> HiCloudAnalysisReport:
    """Return a pre-populated analysis report."""
    report = HiCloudAnalysisReport()
    report.timestamp = datetime.now(timezone.utc).isoformat()
    return report


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Huawei HiCloud Update Protocol Analysis",
    )
    parser.add_argument("--json", dest="json_output", help="Save as JSON")
    parser.add_argument(
        "--download", dest="download_url", default=None,
        help="Download firmware from HiCloud URL",
    )
    parser.add_argument(
        "--decode-url", dest="decode_url", default=None,
        help="Decode a HiCloud download URL into components",
    )
    parser.add_argument(
        "--analyze", dest="analyze_file", default=None,
        help="Analyze a firmware binary file (signatures, HWNP, ELF, scripts)",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("."),
        help="Output directory for downloads",
    )
    args = parser.parse_args()

    report = get_report()

    if args.decode_url:
        decoded = decode_download_url(args.decode_url)
        print(json.dumps(decoded, indent=2))
    elif args.download_url:
        filename = args.download_url.rstrip("/").rsplit("/", 1)[-1]
        dest = args.output_dir / filename
        result = download_firmware_from_hicloud(
            args.download_url, dest, verbose=True,
        )
        print(json.dumps(result, indent=2, default=str))
    elif args.analyze_file:
        result = analyze_firmware_binary(args.analyze_file, verbose=True)
        # Print summary
        hdr = result.get("header", {})
        print(f"\n{'=' * 70}")
        print(f"FIRMWARE ANALYSIS SUMMARY")
        print(f"{'=' * 70}")
        print(f"  File:    {result['file']}")
        print(f"  Size:    {result.get('size_bytes', 0):,} bytes")
        print(f"  MD5:     {result.get('md5', 'N/A')}")
        print(f"  SHA256:  {result.get('sha256', 'N/A')}")
        print(f"  Format:  {hdr.get('format', 'Unknown')}")
        print(f"  Encrypted: {hdr.get('encrypted', False)}")

        sigs = result.get("signatures", [])
        print(f"\n  Signatures: {len(sigs)}")
        for s in sigs[:15]:
            print(f"    {s['offset_hex']}: {s['signature']}")

        hwnp = result.get("hwnp_sections", [])
        if hwnp:
            print(f"\n  HWNP sections: {len(hwnp)}")
            for h in hwnp:
                print(f"    {h['offset_hex']}: {h.get('size', 0):,} bytes"
                      f"  {h.get('product_list', '')[:60]}")

        elfs = result.get("elf_binaries", [])
        if elfs:
            print(f"\n  ELF binaries: {len(elfs)}")
            for e in elfs:
                print(f"    {e.get('offset_hex', '?')}: "
                      f"{e.get('architecture', '?')} {e.get('class', '')}")
                for lib in e.get("libraries", [])[:5]:
                    print(f"      → {lib}")

        scripts = result.get("shell_scripts", [])
        if scripts:
            print(f"\n  Shell scripts: {len(scripts)}")
            for s in scripts:
                print(f"    {s['offset_hex']}: {s['first_line'][:60]} "
                      f"({s['size']:,} chars)")
                if s.get("functions"):
                    print(f"      Functions: {', '.join(s['functions'][:5])}")

        dec = result.get("decryption", {})
        if dec:
            print(f"\n  Decryption: "
                  f"{'SUCCESS' if dec.get('decrypted') else 'FAILED'}")
            if dec.get("analysis"):
                print(f"    {dec['analysis'][:200]}")

        if args.json_output:
            # Remove full script content for JSON output (too large)
            result.pop("shell_scripts_full", None)
    else:
        report.print_summary()

    if args.json_output:
        path = report.save(Path(args.json_output))
        print(f"\nReport saved to: {path}")


if __name__ == "__main__":
    main()
