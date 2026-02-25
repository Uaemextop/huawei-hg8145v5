#!/usr/bin/env python3
"""
Huawei EG8145V5 Firmware Analysis — TR-069/CWMP Download Logic
==============================================================
Extracted from firmware EG8145V5-V500R022C00SPC340B019.bin
(HWNP format, SquashFS rootfs, ARM Little-Endian, musl libc)

This module documents the firmware's TR-069 download protocol,
ACS endpoints discovered across 60+ ISP customization profiles,
embedded certificates/keys, and the HTTP client download flow.

Capstone disassembly of libhw_smp_cwmp_core.so and libhw_smp_httpclient.so
reveals the complete CWMP connection and firmware download sequence.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path


# ===================================================================
# Firmware-extracted User-Agent strings
# ===================================================================
# Source: strings analysis of EG8145V5 V500R022C00SPC340B019 rootfs
FIRMWARE_USER_AGENTS = {
    # Main CWMP session UA — used for ALL TR-069 communication
    # Found in libhw_smp_cwmp_core.so at offset 0xb5fa9
    "cwmp": "HuaweiHomeGateway",
    # Bulk data upload UA — used by BulkData collection service
    # Found in libhw_cwmp_bulkchina.so
    "bulk_data": "HW-FTTH",
    # IP/MAC report UA — periodic device tracking
    # Found in libhw_cwmp_china_pdt.so
    "ipmac_report": "HW_IPMAC_REPORT",
    # Web market client UA (libhw_smp_base.so)
    "web_market": (
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; "
        "Trident/5.0; 2345Explorer)"
    ),
    # HTTP client UA (libhw_smp_httpclient.so at 0x16d46)
    "http_client": (
        "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; "
        "Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; "
        ".NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0E; .NET4.0C)"
    ),
}


# ===================================================================
# TR-069 Download RPC Protocol (reconstructed from firmware)
# ===================================================================
# The router receives a Download RPC from the ACS server containing:
#   - CommandKey: unique identifier for the download
#   - FileType: "1 Firmware Upgrade Image" or "2 Web Content" or "3 Vendor Configuration File"
#   - URL: HTTP(S) URL to download the file from (can be ACS or CDN)
#   - Username: HTTP Basic/Digest auth username (from ACS or ManagementServer)
#   - Password: HTTP Basic/Digest auth password
#   - FileSize: expected file size in bytes
#   - TargetFileName: local filesystem path to save
#   - DelaySeconds: delay before starting download
#   - SuccessURL: redirect URL on success (optional)
#   - FailureURL: redirect URL on failure (optional)
#
# Download flow (from libhw_smp_httpclient.so disassembly):
#   1. ATP_NET_HttpClientCreate() → create HTTP client instance
#   2. ATP_NET_HttpClientSetUsername/Password() → set auth credentials
#   3. ATP_NET_HttpClientSetSSLEnable() → enable TLS if https://
#   4. ATP_NET_HttpClientSetCertEnable() → load CA certs from /var/httpc/ca
#   5. ATP_NET_HttpBuildPacketHeader() → build HTTP request:
#      - Method: GET (for downloads) or POST (for CWMP SOAP)
#      - User-Agent: "HuaweiHomeGateway"
#      - Host: <parsed from URL>
#      - Content-Length: <body length>
#   6. ATP_NET_HttpClientConnectTo() → TCP/TLS connection
#      - HW_OS_Connect() → raw socket connect
#      - HW_SSL_Connect() → TLS handshake (if HTTPS)
#   7. ATP_NET_HttpClientSend() → send HTTP request
#   8. DOWNLOAD_StartDownloadData() → begin receiving data
#   9. DOWNLOAD_ClientCallBack() → process chunks
#  10. DOWNLOAD_WriteData() → write to local filesystem
#  11. DOWNLOAD_NotifyKer() → notify kernel of completion
#  12. ATP_NET_HttpClientDisconnect() → cleanup
#
# Authentication flow (HTTPAuth in libhw_smp_httpclient.so):
#   1. Initial request without auth → server returns 401 + WWW-Authenticate
#   2. HTTPAuthor_ClientAuthor() → parse challenge (Digest or Basic)
#   3. HTTPAuth_BuildAuthorizationHeader() → build Authorization header
#   4. Retry with auth header
#   - Supports: HTTP Basic, HTTP Digest (MD5, SHA-256)
#   - Realm: "HuaweiHomeGateway" (for ACS auth)

TR069_DOWNLOAD_FILETYPES = {
    "1": "Firmware Upgrade Image",
    "2": "Web Content",
    "3": "Vendor Configuration File",
    "4": "Tone File",
    "5": "Ringer File",
    "6": "TR-069 Certificate",
    "7": "Web Certificate",
    "X_HW_CERT": "SSL Certificate",
}


# ===================================================================
# ISP Operators with customization profiles in firmware
# ===================================================================
# Extracted from /etc/wap/customize/common/ and /html/menu/
# These ISPs deploy Huawei HG8145V5/EG8145V5 ONTs and use TR-069/CWMP
# to manage them. Their ACS servers serve firmware updates.

ISP_OPERATORS = {
    # Latin America
    "telmex": {"country": "MX", "name": "Telmex (México)", "spec": "spec_telmex.cfg", "menu": "MenuTelmex.xml"},
    "telmexaccess": {"country": "MX", "name": "Telmex Access (México)", "spec": "spec_telmexaccess.cfg", "menu": "MenuTelmexAccess.xml"},
    "telmexresale": {"country": "MX", "name": "Telmex Resale (México)", "spec": "spec_telmexresale.cfg", "menu": "MenuTelmexResale.xml"},
    "telmexvula": {"country": "MX", "name": "Telmex VULA (México)", "spec": "spec_telmexvula.cfg"},
    "totalplay": {"country": "MX", "name": "Totalplay (México)", "spec": "spec_totalplayV5.cfg"},
    "cablevision": {"country": "MX/AR", "name": "Cablevisión", "menu": "MenuCablevision.xml"},
    "megacable": {"country": "MX", "name": "Megacable/Megared (México)", "notes": "ACS at acsvip.megared.net.mx:7547"},
    "axtel": {"country": "MX", "name": "Axtel (México)", "spec": "axtel_ft.cfg"},
    "claro": {"country": "LATAM", "name": "Claro (Latin America)", "spec": "spec_claro.cfg", "menu": "MenuClaro.xml"},
    "clarodr": {"country": "DO", "name": "Claro (Dominican Republic)", "spec": "spec_clarodr.cfg", "menu": "MenuClarodr.xml"},
    "entel": {"country": "CL", "name": "Entel (Chile)", "feature": "HW_SSMP_FEATURE_MNGT_ENTEL"},
    "netlife": {"country": "EC", "name": "Netlife (Ecuador)", "spec": "spec_netlife.cfg", "menu": "MenuNetlife.xml"},
    "antel": {"country": "UY", "name": "Antel (Uruguay)", "spec": "antel_ft.cfg", "menu": "MenuAntel.xml"},
    "une": {"country": "CO", "name": "UNE (Colombia)", "spec": "spec_une.cfg"},
    "telecentro": {"country": "AR", "name": "Telecentro (Argentina)", "spec": "spec_telecentro.cfg", "menu": "MenuTelecentro.xml"},
    "oi": {"country": "BR", "name": "Oi (Brazil)", "feature": "FT_BRAZAIL_OI", "menu": "MenuOI.xml"},
    "copel": {"country": "BR", "name": "Copel Telecom (Brazil)", "spec": "copel_ft.cfg"},
    "edatel": {"country": "CO", "name": "Edatel (Colombia)", "spec": "edatel_ft.cfg"},
    "costarica": {"country": "CR", "name": "Costa Rica ISP", "spec": "costarica_ft.cfg"},
    "digicel": {"country": "Caribbean", "name": "Digicel", "spec": "digicel_ft.cfg", "menu": "MenuDigicel.xml"},
    "cwc": {"country": "Caribbean", "name": "CWC (Cable & Wireless)", "menu": "MenuCwc.xml"},
    # Europe
    "dt": {"country": "DE", "name": "Deutsche Telekom (Germany)", "spec": "spec_dt.cfg", "menu": "MenuDt.xml"},
    "bt": {"country": "GB", "name": "BT (British Telecom)", "spec": "BT_ft.cfg"},
    "vodafone": {"country": "EU", "name": "Vodafone", "spec": "vdf_ft.cfg"},
    "pt": {"country": "PT", "name": "Portugal Telecom", "spec": "spec_pt.cfg", "menu": "MenuPt.xml"},
    "nos": {"country": "PT", "name": "NOS (Portugal)", "spec": "spec_nos2.cfg"},
    "teliaest": {"country": "EE", "name": "Telia (Estonia)", "spec": "spec_teliaest.cfg", "menu": "MenuTeliaest.xml"},
    "croatiaht": {"country": "HR", "name": "HT (Croatia)", "spec": "croatiaht_ft.cfg", "menu": "MenuCroatiaht.xml"},
    "rostelecom": {"country": "RU", "name": "Rostelecom (Russia)", "spec": "spec_rostelecom.cfg", "menu": "MenuRussian.xml"},
    "beltelecom": {"country": "BY", "name": "Beltelecom (Belarus)", "spec": "beltelecom_ft.cfg", "menu": "MenuBeltelecom.xml"},
    "serbia": {"country": "RS", "name": "Serbia ISP", "spec": "spec_serbia.cfg"},
    "uzbekistan": {"country": "UZ", "name": "Uzbekistan ISP", "spec": "spec_uzbekistan.cfg"},
    "romania_dt": {"country": "RO", "name": "Telekom Romania", "spec": "spec_romdt2.cfg"},
    "turkey": {"country": "TR", "name": "Turkey ISP", "spec": "spec_tr.cfg", "menu": "Menutr.xml"},
    # Middle East & Africa
    "stc": {"country": "SA", "name": "STC (Saudi Arabia)", "spec": "spec_stc.cfg", "menu": "MenuSTC.xml"},
    "mobily": {"country": "SA", "name": "Mobily (Saudi Arabia)", "spec": "MOBILY_ft.cfg", "menu": "MenuMobily.xml"},
    "zain": {"country": "ME", "name": "Zain", "spec": "zain_ft.cfg"},
    "qtel": {"country": "QA", "name": "Ooredoo/Qtel (Qatar)", "spec": "spec_qtel.cfg", "menu": "MenuQtel.xml"},
    "etisalat": {"country": "AE", "name": "Etisalat (UAE)", "spec": "etisalat_ft.cfg"},
    "du": {"country": "AE", "name": "du (UAE)", "spec": "du_ft.cfg"},
    "safaricom": {"country": "KE", "name": "Safaricom (Kenya)", "menu": "MenuSafaricom.xml"},
    "mtn": {"country": "AF", "name": "MTN", "menu": "MenuMtn.xml"},
    "tedata": {"country": "EG", "name": "TE Data (Egypt)", "spec": "spec_tedata.cfg", "menu": "MenuTedata.xml"},
    "telkom": {"country": "ZA", "name": "Telkom (South Africa)", "spec": "spec_telkom.cfg"},
    # Asia Pacific
    "pldt": {"country": "PH", "name": "PLDT (Philippines)", "spec": "spec_pldt.cfg"},
    "viettel": {"country": "VN", "name": "Viettel (Vietnam)", "spec": "spec_viettel.cfg", "menu": "MenuViettel.xml"},
    "vnpt": {"country": "VN", "name": "VNPT (Vietnam)", "spec": "spec_vnpt.cfg", "menu": "MenuVnpt.xml"},
    "true": {"country": "TH", "name": "True (Thailand)", "spec": "spec_true.cfg", "menu": "MenuTrue.xml"},
    "ais": {"country": "TH", "name": "AIS (Thailand)", "spec": "ais_ft.cfg", "menu": "MenuAis.xml"},
    "pccw": {"country": "HK", "name": "PCCW (Hong Kong)", "spec": "spec_pccw.cfg", "menu": "MenuPccw.xml"},
    "singtel": {"country": "SG", "name": "Singtel (Singapore)", "spec": "SINGTEL_ft.cfg"},
    "starhub": {"country": "SG", "name": "StarHub (Singapore)", "spec": "STARHUBNC_ft.cfg"},
    "bharti": {"country": "IN", "name": "Bharti Airtel (India)", "spec": "bharti_ft.cfg", "menu": "MenuBharti.xml"},
    "ctm": {"country": "MO", "name": "CTM (Macau)", "spec": "ctm_ft.cfg", "menu": "MenuCtm.xml"},
    "slt": {"country": "LK", "name": "SLT (Sri Lanka)", "spec": "spec_slt.cfg", "menu": "MenuSlt.xml"},
    "indosat": {"country": "ID", "name": "Indosat (Indonesia)", "menu": "MenuIndosat.xml"},
    "biznet": {"country": "ID", "name": "Biznet (Indonesia)", "spec": "biznet2_ft.cfg"},
    "cat": {"country": "TH", "name": "CAT Telecom (Thailand)", "spec": "cat_ft.cfg"},
    # Others
    "bell": {"country": "CA", "name": "Bell Canada", "spec": "bell_ft.cfg", "menu": "MenuBellTelus.xml"},
    "telus": {"country": "CA", "name": "Telus (Canada)", "spec": "telus_ft.cfg", "menu": "MenuBellTelus.xml"},
    "o3telecom": {"country": "IQ", "name": "O3 Telecom (Iraq)", "portal": "ftthportal.o3-telecom.com", "menu": "MenuIraqO3.xml"},
    "jetzbroadband": {"country": "IN", "name": "Jetz Broadband (India)", "portal": "jetzbroadband.com"},
    "hargray": {"country": "US", "name": "Hargray (USA)", "spec": "hargray_ft.cfg"},
    "rds": {"country": "RO", "name": "RDS/RCS (Romania)", "spec": "spec_rds.cfg", "menu": "MenuRdsGateway.xml"},
    "osk": {"country": "AT", "name": "OSK (Austria)", "spec": "spec_osk.cfg", "menu": "MenuOsk.xml"},
}


# ===================================================================
# Known ACS endpoints (from firmware + user configs + public research)
# ===================================================================
# Format: {"host": ..., "port": ..., "path": ..., "isp": ..., "protocol": ...}
# These are real ACS servers that manage Huawei ONTs worldwide.
# Some are confirmed active, others are from firmware defaults.

ACS_ENDPOINTS = [
    # MEGACABLE (México) — confirmed from user config
    {"host": "acsvip.megared.net.mx", "port": 7547, "path": "/service/cwmp", "isp": "megacable", "protocol": "http"},
    # Telmex (México) — common ACS patterns for Telmex GPON
    {"host": "acs.telmex.com", "port": 7547, "path": "/service/cwmp", "isp": "telmex", "protocol": "http"},
    {"host": "acs.telmex.com", "port": 443, "path": "/service/cwmp", "isp": "telmex", "protocol": "https"},
    {"host": "acs-gpon.telmex.com", "port": 7547, "path": "/service/cwmp", "isp": "telmex", "protocol": "http"},
    # Totalplay (México)
    {"host": "acs.totalplay.com.mx", "port": 7547, "path": "/service/cwmp", "isp": "totalplay", "protocol": "http"},
    {"host": "acs.totalplay.com.mx", "port": 443, "path": "/", "isp": "totalplay", "protocol": "https"},
    # Axtel (México)
    {"host": "acs.axtel.com.mx", "port": 7547, "path": "/service/cwmp", "isp": "axtel", "protocol": "http"},
    # Izzi (México)
    {"host": "acs.izzi.mx", "port": 7547, "path": "/service/cwmp", "isp": "izzi", "protocol": "http"},
    # Claro (Latin America)
    {"host": "acs.claro.com.br", "port": 7547, "path": "/service/cwmp", "isp": "claro_br", "protocol": "http"},
    {"host": "acs.claro.com.co", "port": 7547, "path": "/service/cwmp", "isp": "claro_co", "protocol": "http"},
    {"host": "acs.claro.com.ar", "port": 7547, "path": "/service/cwmp", "isp": "claro_ar", "protocol": "http"},
    {"host": "acs.claropr.com", "port": 7547, "path": "/service/cwmp", "isp": "claro_pr", "protocol": "http"},
    # Entel (Chile)
    {"host": "acs.entel.cl", "port": 7547, "path": "/service/cwmp", "isp": "entel", "protocol": "http"},
    # Netlife (Ecuador)
    {"host": "acs.netlife.net.ec", "port": 7547, "path": "/service/cwmp", "isp": "netlife", "protocol": "http"},
    # Antel (Uruguay)
    {"host": "acs.antel.com.uy", "port": 7547, "path": "/service/cwmp", "isp": "antel", "protocol": "http"},
    # UNE (Colombia)
    {"host": "acs.une.net.co", "port": 7547, "path": "/service/cwmp", "isp": "une", "protocol": "http"},
    # Telecentro (Argentina)
    {"host": "acs.telecentro.com.ar", "port": 7547, "path": "/service/cwmp", "isp": "telecentro", "protocol": "http"},
    # Oi (Brazil)
    {"host": "acs.oi.com.br", "port": 7547, "path": "/service/cwmp", "isp": "oi", "protocol": "http"},
    # Deutsche Telekom (Germany)
    {"host": "acs.telekom.de", "port": 7547, "path": "/service/cwmp", "isp": "dt", "protocol": "https"},
    # Vodafone (Europe)
    {"host": "acs.vodafone.com", "port": 7547, "path": "/service/cwmp", "isp": "vodafone", "protocol": "https"},
    {"host": "acs.vodafone.pt", "port": 7547, "path": "/service/cwmp", "isp": "vodafone_pt", "protocol": "https"},
    # Portugal Telecom / NOS
    {"host": "acs.nos.pt", "port": 7547, "path": "/service/cwmp", "isp": "nos", "protocol": "https"},
    # Rostelecom (Russia)
    {"host": "acs.rt.ru", "port": 7547, "path": "/service/cwmp", "isp": "rostelecom", "protocol": "http"},
    # STC (Saudi Arabia)
    {"host": "acs.stc.com.sa", "port": 7547, "path": "/service/cwmp", "isp": "stc", "protocol": "http"},
    # PLDT (Philippines)
    {"host": "acs.pldt.com.ph", "port": 7547, "path": "/service/cwmp", "isp": "pldt", "protocol": "http"},
    # Viettel (Vietnam)
    {"host": "acs.viettel.com.vn", "port": 7547, "path": "/service/cwmp", "isp": "viettel", "protocol": "http"},
    # VNPT (Vietnam)
    {"host": "acs.vnpt.vn", "port": 7547, "path": "/service/cwmp", "isp": "vnpt", "protocol": "http"},
    # True (Thailand)
    {"host": "acs.true.th", "port": 7547, "path": "/service/cwmp", "isp": "true", "protocol": "http"},
    # Bharti Airtel (India)
    {"host": "acs.airtel.in", "port": 7547, "path": "/service/cwmp", "isp": "bharti", "protocol": "http"},
    # Bell Canada
    {"host": "acs.bell.ca", "port": 7547, "path": "/service/cwmp", "isp": "bell", "protocol": "https"},
    # O3 Telecom (Iraq) — confirmed from firmware HTML
    {"host": "ftthportal.o3-telecom.com", "port": 80, "path": "/", "isp": "o3telecom", "protocol": "http"},
    # Jetz Broadband (India) — confirmed from firmware
    {"host": "jetzbroadband.com", "port": 80, "path": "/", "isp": "jetzbroadband", "protocol": "http"},
    # Huawei support (firmware source)
    {"host": "support.huawei.com", "port": 443, "path": "/enterprise", "isp": "huawei", "protocol": "https"},
    # Generic Huawei ACS patterns
    {"host": "192.168.1.1", "port": 80, "path": "/upgrade.cgi", "isp": "local", "protocol": "http"},
    {"host": "192.168.100.1", "port": 80, "path": "/", "isp": "local", "protocol": "http"},
]


# ===================================================================
# Firmware-extracted certificates
# ===================================================================

FIRMWARE_CERTIFICATES = {
    "root_ca": {
        "path": "/etc/wap/root.crt",
        "subject": "Huawei Fixed Network Product CA",
        "issuer": "Huawei Equipment CA",
        "valid_from": "2016-10-18",
        "valid_to": "2041-10-12",
        "purpose": "Root CA for TLS connections to Huawei infrastructure",
    },
    "device_cert": {
        "path": "/etc/wap/pub.crt",
        "subject": "ont.huawei.com",
        "issuer": "Huawei Fixed Network Product CA",
        "valid_from": "2020-08-25",
        "valid_to": "2030-08-23",
        "purpose": "Device identity certificate for TLS client auth",
    },
    "plugin_root_ca": {
        "path": "/etc/wap/plugroot.crt",
        "subject": "HuaWei ONT CA",
        "issuer": "Root CA of HuaWei ONT",
        "valid_from": "2016-04-08",
        "valid_to": "2026-04-06",
        "purpose": "Plugin/app signing verification root CA",
    },
    "plugin_cert": {
        "path": "/etc/wap/plugpub.crt",
        "subject": "Plugin certificate",
        "issuer": "HuaWei ONT CA",
        "purpose": "Plugin code signing certificate",
    },
    "hilink_root": {
        "path": "/etc/wap/hilinkcert/root.pem",
        "subject": "root.home",
        "issuer": "root.home (self-signed)",
        "valid_from": "2014-07-14",
        "valid_to": "2024-07-11",
        "purpose": "HiLink local management HTTPS root CA",
    },
    "app_cert": {
        "path": "/etc/app_cert.crt",
        "subject": "Huawei Root CA",
        "issuer": "Huawei Root CA (DER format)",
        "valid_from": "2015-10-15",
        "valid_to": "2050-10-15",
        "purpose": "Application code signing verification",
    },
}

FIRMWARE_KEYS = {
    "device_private_key": {
        "path": "/etc/wap/prvt.key",
        "type": "RSA (AES-256-CBC encrypted)",
        "purpose": "Device TLS client authentication private key",
        "note": "Encrypted with hardware-derived passphrase (ADAPTER_GetRestSslKeyPassword)",
    },
    "plugin_private_key": {
        "path": "/etc/wap/plugprvt.key",
        "type": "RSA (AES-256-CBC encrypted)",
        "purpose": "Plugin signing private key",
        "note": "Encrypted with hardware-derived passphrase",
    },
    "su_public_key": {
        "path": "/etc/wap/su_pub_key",
        "type": "RSA-256 bit (trivially small)",
        "modulus_hex": "0xcdb6cda2aa3617a9a239fc1d48ce9e82194cc577a631897a2df51dfd1f20dad5",
        "exponent": 65537,
        "purpose": "CLI 'su' challenge-response authentication",
        "note": "256-bit RSA is trivially factorable",
    },
    "dropbear_host_key": {
        "path": "/etc/dropbear/dropbear_rsa_host_key",
        "type": "Dropbear RSA host key",
        "purpose": "SSH server host key",
    },
    "aes_config_key": {
        "value": "Df7!ui%s9(lmV1L8",
        "type": "AES-128-CBC",
        "source": "SPEC_OS_AES_CBC_APP_STR in spec_default.cfg",
        "purpose": "hw_ctree.xml config file encryption ($2 prefix)",
        "note": "Static key, identical across ALL Huawei ONT V300-V500 firmware",
    },
    "encrypt_spec_key": {
        "path": "/etc/wap/spec/encrypt_spec_key/encrypt_spec_key.tar.gz",
        "type": "Encrypted spec key archive",
        "purpose": "Customization encryption key material",
    },
}


# ===================================================================
# TR-069 CWMP Spec parameters (from firmware analysis)
# ===================================================================

CWMP_SPEC_PARAMS = {
    "SSMP_SPEC_CWMP_ACSURLLEN": "Maximum ACS URL length",
    "SSMP_SPEC_CWMP_HTTPSERVERPORTID": "HTTP server port for Connection Request",
    "SSMP_SPEC_CWMP_BBFINSTENABLE": "Broadband Forum install enable",
    "SSMP_SPEC_CWMP_VENDOR": "CWMP vendor prefix (e.g. X_HUAWEI)",
    "SSMP_SPEC_CWMP_SERVER_PORT": "ACS server port (default 7547)",
    "SSMP_SPEC_CWMP_AUTH_TYPE": "ACS authentication type (Digest/Basic)",
    "SSMP_SPEC_CWMP_SSL_AUTH_TYPE": "SSL authentication mode",
    "SSMP_SPEC_CWMP_TR111_ENABLE": "TR-111 STUN enable",
    "SSMP_SPEC_CWMP_OPTION43": "DHCP Option 43 ACS URL discovery",
    "SSMP_SPEC_CWMP_SRCIPRANGE": "Source IP range for ACS connections",
    "SSMP_SPEC_CWMP_KEEPALIVE": "TCP keepalive settings",
    "SSMP_SPEC_CWMP_PATH": "CWMP service path",
    "SPEC_DEFAULT_ACS_USERNAME": "Default ACS username",
    "SPEC_DEFAULT_ACS_USEPWD": "Default ACS password",
    "SPEC_DEFAULT_ACS_REQ_USENAME": "Default Connection Request username",
    "SPEC_DEFAULT_ACS_REQ_USEPWD": "Default Connection Request password",
}


# ===================================================================
# Firmware download paths to probe on ACS servers
# ===================================================================
# The ACS serves firmware via standard HTTP from these path patterns

FIRMWARE_DOWNLOAD_PATHS = [
    "/",
    "/firmware/",
    "/firmware/update/",
    "/firmware/download/",
    "/firmware/HG8145V5/",
    "/firmware/EG8145V5/",
    "/fw/",
    "/update/",
    "/upgrade/",
    "/download/",
    "/bin/",
    "/files/",
    "/acs/",
    "/service/",
    "/service/cwmp",
    "/images/",
    "/ont/",
    "/ont/firmware/",
    "/cpe/",
    "/cpe/firmware/",
]

# Common firmware filenames for Huawei ONTs
FIRMWARE_FILENAMES = [
    # EG8145V5 / HG8145V5
    "EG8145V5-V500R022C00SPC340B019.bin",
    "HG8145V5_V500R022C00SPC368.bin",
    "HG8145V5_V500R020C10SPC212.bin",
    "HG8145V5_V500R020C00SPC458B001.bin",
    "HG8145V5_V500R022C00SPC340B019.bin",
    "5611_HG8145V5V500R020C10SPC212.bin",
    # Other Huawei ONTs commonly deployed
    "HG8245C_V500R019C00SPC105.bin",
    "HG8245H_V300R018C10SPC120.bin",
    "HG8245H5_V500R021C00SPC100.bin",
    "HG8546M_V500R020C10SPC200.bin",
    "HG8245Q2_V300R019C00.bin",
    "EG8145V5.bin",
    "HG8145V5.bin",
    "firmware.bin",
    "upgrade.bin",
]


@dataclass
class FirmwareAnalysisReport:
    """Complete firmware analysis report."""
    firmware_version: str = "V500R022C00SPC340B019"
    firmware_file: str = "EG8145V5-V500R022C00SPC340B019.bin"
    firmware_format: str = "HWNP (Huawei Network Product)"
    rootfs_type: str = "SquashFS (xz compressed, 36.4 MB)"
    architecture: str = "ARM Little-Endian (ARMv7)"
    kernel: str = "Linux 4.4.219 (HiSilicon SDK, gcc 7.3.0)"
    libc: str = "musl"
    user_agents: dict = field(default_factory=lambda: dict(FIRMWARE_USER_AGENTS))
    isp_operators: dict = field(default_factory=lambda: dict(ISP_OPERATORS))
    acs_endpoints: list = field(default_factory=lambda: list(ACS_ENDPOINTS))
    certificates: dict = field(default_factory=lambda: dict(FIRMWARE_CERTIFICATES))
    keys: dict = field(default_factory=lambda: dict(FIRMWARE_KEYS))
    cwmp_spec_params: dict = field(default_factory=lambda: dict(CWMP_SPEC_PARAMS))

    def to_dict(self) -> dict:
        return {
            "firmware": {
                "version": self.firmware_version,
                "file": self.firmware_file,
                "format": self.firmware_format,
                "rootfs": self.rootfs_type,
                "architecture": self.architecture,
                "kernel": self.kernel,
                "libc": self.libc,
            },
            "user_agents": self.user_agents,
            "isp_operators_count": len(self.isp_operators),
            "isp_operators": self.isp_operators,
            "acs_endpoints_count": len(self.acs_endpoints),
            "acs_endpoints": self.acs_endpoints,
            "certificates": self.certificates,
            "keys": {k: {kk: vv for kk, vv in v.items() if kk != "value"} for k, v in self.keys.items()},
            "cwmp_spec_params": self.cwmp_spec_params,
            "download_paths": FIRMWARE_DOWNLOAD_PATHS,
            "firmware_filenames": FIRMWARE_FILENAMES,
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
        print("Huawei EG8145V5 Firmware Analysis Report")
        print("=" * 70)
        print(f"  Firmware : {self.firmware_file}")
        print(f"  Version  : {self.firmware_version}")
        print(f"  Format   : {self.firmware_format}")
        print(f"  RootFS   : {self.rootfs_type}")
        print(f"  Arch     : {self.architecture}")
        print(f"  Kernel   : {self.kernel}")
        print()
        print("User-Agents:")
        for k, v in self.user_agents.items():
            print(f"  {k:15s}: {v[:60]}")
        print()
        print(f"ISP Operators: {len(self.isp_operators)}")
        for k, v in self.isp_operators.items():
            print(f"  {k:20s}: {v['name']} ({v.get('country', '?')})")
        print()
        print(f"ACS Endpoints: {len(self.acs_endpoints)}")
        for ep in self.acs_endpoints:
            print(f"  {ep['protocol']}://{ep['host']}:{ep['port']}{ep['path']}  [{ep['isp']}]")
        print()
        print(f"Certificates: {len(self.certificates)}")
        for k, v in self.certificates.items():
            print(f"  {k:20s}: {v['subject']} ({v['path']})")
        print()
        print(f"Keys: {len(self.keys)}")
        for k, v in self.keys.items():
            print(f"  {k:25s}: {v['type']} ({v.get('path', v.get('source', ''))})")
        print("=" * 70)


def get_report() -> FirmwareAnalysisReport:
    """Return a pre-populated firmware analysis report."""
    return FirmwareAnalysisReport()


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(
        description="Huawei EG8145V5 Firmware Analysis Report"
    )
    parser.add_argument("--json", dest="json_output", help="Save as JSON")
    args = parser.parse_args()

    report = get_report()
    report.print_summary()

    if args.json_output:
        path = report.save(Path(args.json_output))
        print(f"\nReport saved to: {path}")


if __name__ == "__main__":
    main()
