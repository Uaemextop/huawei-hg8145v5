#!/usr/bin/env python3
"""
TR-069 ACS (Auto Configuration Server) / CWMP Server
for Huawei HG8145V5 Router Management.

A local TR-069 Auto Configuration Server that speaks the CWMP (CPE WAN
Management Protocol) over SOAP/HTTP.  Designed specifically for the
Huawei HG8145V5 ONT/router (MEGACABLE firmware V500R022C00SPC368),
supporting both TR-098 (InternetGatewayDevice.) and TR-181-2-11-0
(Device.) data models with automatic detection.

Data model: urn:broadband-forum-org:tr-181-2-11-0 (VOICE,WIFI,Router)
ISP ACS:    http://acsvip.megared.net.mx:7547/service/cwmp
Username:   AdminGPON / ConnReq: ONTconnect

Usage:
    # Start the ACS and wait for the CPE to connect
    python tools/tr069_server.py --listen 0.0.0.0 --port 7547

    # Dump the full device configuration to JSON
    python tools/tr069_server.py --action dump-all --output config.json

    # Enable Telnet on the LAN side
    python tools/tr069_server.py --action enable-telnet

    # Extract all stored credentials (web, ACS, PPPoE, VoIP, GPON, remote)
    python tools/tr069_server.py --action extract-creds --output creds.json

    # Trigger a CPE connection and extract WiFi keys (full: both bands)
    python tools/tr069_server.py --action extract-wifi-full \\
        --cpe-url http://192.168.100.1:7547/ --output wifi.json

    # Extract remote management credentials (X_HW_AppRemoteManage)
    python tools/tr069_server.py --action extract-remote-mgmt

    # Change ACS URL to point at this server
    python tools/tr069_server.py --action change-acs

    # Reboot the device
    python tools/tr069_server.py --action reboot

Supported actions:
    dump-config          GetParameterValues on standard paths -> JSON
    dump-all             GetParameterValues on ALL known paths (extended)
    enable-telnet        Enable Telnet access on LAN
    enable-ssh           Enable SSH access on LAN
    extract-creds        Extract all stored credentials
    extract-certs        Extract certificates, private keys, cert passwords
    extract-wifi         Extract WiFi SSID and PSK (basic)
    extract-wifi-full    Extract full WiFi config (both bands, WPS, guests)
    extract-gpon         Extract GPON/ONT parameters
    extract-remote-mgmt  Extract X_HW_AppRemoteManage admin/user creds
    change-acs           Redirect ACS URL to this server
    change-dns           Change upstream DNS servers
    reboot               Reboot the CPE
    factory-reset        Factory reset the CPE
    open-wan-mgmt        Enable WAN-side HTTP/Telnet/SSH management
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import html
import http.server
import io
import json
import logging
import os
import re
import socket
import sys
import textwrap
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from functools import partial
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("tr069_server")

# ---------------------------------------------------------------------------
# CWMP / SOAP XML namespaces
# ---------------------------------------------------------------------------
NS_SOAP_ENV = "http://schemas.xmlsoap.org/soap/envelope/"
NS_SOAP_ENC = "http://schemas.xmlsoap.org/soap/encoding/"
NS_XSD = "http://www.w3.org/2001/XMLSchema"
NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"
NS_CWMP = "urn:dslforum-org:cwmp-1-0"

SOAP_NS_MAP = {
    "soapenv": NS_SOAP_ENV,
    "soapenc": NS_SOAP_ENC,
    "xsd": NS_XSD,
    "xsi": NS_XSI,
    "cwmp": NS_CWMP,
}

# Register namespaces so ET.tostring uses nice prefixes
for prefix, uri in SOAP_NS_MAP.items():
    ET.register_namespace(prefix, uri)

# ---------------------------------------------------------------------------
# Supported Data Models
# ---------------------------------------------------------------------------
# The HG8145V5 (MEGACABLE firmware V500R022C00SPC368) advertises:
#   urn:broadband-forum-org:tr-181-2-11-0  (Device.2 root)
# but the internal configuration XML still uses the TR-098 root
# (InternetGatewayDevice.).  Both roots are provided so the tool
# works regardless of what the CPE actually responds with.
# ---------------------------------------------------------------------------

SUPPORTED_DATA_MODEL = {
    "url": "https://www.broadband-forum.org/cwmp/tr-181-2-11-0-full.xml",
    "uuid": "8862c186-5884-5341-b9ab-8c350dc33abd",
    "urn": "urn:broadband-forum-org:tr-181-2-11-0",
    "features": "VOICE,WIFI,Router",
}

# Data model roots
TR098_ROOT = "InternetGatewayDevice"
TR181_ROOT = "Device"

class DataModel:
    """Utility to work with both TR-098 and TR-181 parameter paths."""

    TR098 = "TR-098"
    TR181 = "TR-181"

    @staticmethod
    def detect_from_inform(parameters: Dict[str, str]) -> str:
        """Auto-detect data model from Inform parameter names."""
        for name in parameters:
            if name.startswith("Device."):
                return DataModel.TR181
            if name.startswith("InternetGatewayDevice."):
                return DataModel.TR098
        return DataModel.TR098  # default

    @staticmethod
    def translate_paths(
        paths: List[str], target_model: str,
    ) -> List[str]:
        """Convert parameter paths between TR-098 and TR-181."""
        result = []
        for p in paths:
            if target_model == DataModel.TR181:
                result.append(DataModel.to_tr181(p))
            else:
                result.append(DataModel.to_tr098(p))
        return result

    @staticmethod
    def to_tr181(path: str) -> str:
        """Convert a TR-098 path to TR-181 equivalent."""
        if path.startswith("Device."):
            return path
        return _TR098_TO_TR181.get(path, path.replace(
            "InternetGatewayDevice.", "Device.", 1))

    @staticmethod
    def to_tr098(path: str) -> str:
        """Convert a TR-181 path to TR-098 equivalent."""
        if path.startswith("InternetGatewayDevice."):
            return path
        return _TR181_TO_TR098.get(path, path.replace(
            "Device.", "InternetGatewayDevice.", 1))


# Mapping of TR-098 paths that have different TR-181 equivalents
_TR098_TO_TR181: Dict[str, str] = {
    # WAN connections
    "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Username":
        "Device.PPP.Interface.1.Username",
    "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Password":
        "Device.PPP.Interface.1.Password",
    "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress":
        "Device.IP.Interface.1.IPv4Address.1.IPAddress",
    # WLAN
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID":
        "Device.WiFi.SSID.1.SSID",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.PreSharedKey":
        "Device.WiFi.AccessPoint.1.Security.PreSharedKey",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.KeyPassphrase":
        "Device.WiFi.AccessPoint.1.Security.KeyPassphrase",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.SSID":
        "Device.WiFi.SSID.5.SSID",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey.1.PreSharedKey":
        "Device.WiFi.AccessPoint.5.Security.PreSharedKey",
    # DNS
    "InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DNSServers":
        "Device.DHCPv4.Server.Pool.1.DNSServers",
    # Hosts
    "InternetGatewayDevice.LANDevice.1.Hosts.Host.":
        "Device.Hosts.Host.",
}

_TR181_TO_TR098 = {v: k for k, v in _TR098_TO_TR181.items()}

# ---------------------------------------------------------------------------
# MEGACABLE ISP-specific configuration
# ---------------------------------------------------------------------------

MEGACABLE_ISP_CONFIG = {
    "acs_url": "http://acsvip.megared.net.mx:7547/service/cwmp",
    "acs_username": "AdminGPON",
    "conn_req_username": "ONTconnect",
    "periodic_inform_interval": 900,
    "custom_info": "MEGACABLE",
    "custom_info_detail": "megacable",
    "firmware_original": "V500R022C00SPC368A2406290391",
    "firmware_current": "V500R022",
    "x_hw_path": "57352c84da092f5d2e257fe48d9f86c9",
    "local_admin_name": "Mega_gpon",
    "local_user_name": "user",
}

# ---------------------------------------------------------------------------
# Huawei HG8145V5 TR-069 parameter paths (TR-098 root)
# ---------------------------------------------------------------------------

DEVICE_INFO_PARAMS = [
    "InternetGatewayDevice.DeviceInfo.Manufacturer",
    "InternetGatewayDevice.DeviceInfo.ModelName",
    "InternetGatewayDevice.DeviceInfo.SerialNumber",
    "InternetGatewayDevice.DeviceInfo.SoftwareVersion",
    "InternetGatewayDevice.DeviceInfo.HardwareVersion",
    "InternetGatewayDevice.DeviceInfo.ProvisioningCode",
    "InternetGatewayDevice.DeviceInfo.X_HW_UpPortMode",
    "InternetGatewayDevice.DeviceInfo.X_HW_TotalHWReboot",
    "InternetGatewayDevice.DeviceInfo.FirstUseDate",
]

PRODUCT_INFO_PARAMS = [
    "InternetGatewayDevice.X_HW_ProductInfo.originalVersion",
    "InternetGatewayDevice.X_HW_ProductInfo.currentVersion",
    "InternetGatewayDevice.X_HW_ProductInfo.customInfo",
    "InternetGatewayDevice.X_HW_ProductInfo.customInfoDetail",
]

MGMT_SERVER_PARAMS = [
    "InternetGatewayDevice.ManagementServer.EnableCWMP",
    "InternetGatewayDevice.ManagementServer.URL",
    "InternetGatewayDevice.ManagementServer.Username",
    "InternetGatewayDevice.ManagementServer.Password",
    "InternetGatewayDevice.ManagementServer.ConnectionRequestURL",
    "InternetGatewayDevice.ManagementServer.ConnectionRequestUsername",
    "InternetGatewayDevice.ManagementServer.ConnectionRequestPassword",
    "InternetGatewayDevice.ManagementServer.PeriodicInformEnable",
    "InternetGatewayDevice.ManagementServer.PeriodicInformInterval",
    "InternetGatewayDevice.ManagementServer.ParameterKey",
    "InternetGatewayDevice.ManagementServer.UpgradesManaged",
    "InternetGatewayDevice.ManagementServer.STUNEnable",
    "InternetGatewayDevice.ManagementServer.STUNServerAddress",
    "InternetGatewayDevice.ManagementServer.STUNServerPort",
    "InternetGatewayDevice.ManagementServer.X_HW_EnableCertificate",
    "InternetGatewayDevice.ManagementServer.X_HW_CertPassword",
    "InternetGatewayDevice.ManagementServer.X_HW_Certificate",
    "InternetGatewayDevice.ManagementServer.X_HW_PrivateKey",
    "InternetGatewayDevice.ManagementServer.X_HW_DSCP",
    "InternetGatewayDevice.ManagementServer.X_HW_IPProtocolVersion",
    "InternetGatewayDevice.ManagementServer.X_HW_Path",
    "InternetGatewayDevice.ManagementServer.X_HW_EnableCWMP",
]

WEB_USER_PARAMS = [
    "InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.1.UserName",
    "InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.1.Password",
    "InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.2.UserName",
    "InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.2.Password",
    "InternetGatewayDevice.UserInterface.X_HW_WebSslInfo.Enable",
    "InternetGatewayDevice.UserInterface.X_HW_WebSslInfo.CertPassword",
]

REMOTE_MGMT_PARAMS = [
    "InternetGatewayDevice.X_HW_AppRemoteManage.MgtURL",
    "InternetGatewayDevice.X_HW_AppRemoteManage.Port",
    "InternetGatewayDevice.X_HW_AppRemoteManage.Heartbeat",
    "InternetGatewayDevice.X_HW_AppRemoteManage.Ability",
    "InternetGatewayDevice.X_HW_AppRemoteManage.LocatePort",
    "InternetGatewayDevice.X_HW_AppRemoteManage.LocalUserName",
    "InternetGatewayDevice.X_HW_AppRemoteManage.LocalUserPassword",
    "InternetGatewayDevice.X_HW_AppRemoteManage.LocalUserPassMode",
    "InternetGatewayDevice.X_HW_AppRemoteManage.LocalAdminName",
    "InternetGatewayDevice.X_HW_AppRemoteManage.LocalAdminPassword",
    "InternetGatewayDevice.X_HW_AppRemoteManage.LocalAdminPassMode",
]

USER_INFO_PARAMS = [
    "InternetGatewayDevice.X_HW_UserInfo.UserName",
    "InternetGatewayDevice.X_HW_UserInfo.UserId",
    "InternetGatewayDevice.X_HW_UserInfo.Status",
    "InternetGatewayDevice.X_HW_UserInfo.Limit",
    "InternetGatewayDevice.X_HW_UserInfo.Times",
    "InternetGatewayDevice.X_HW_UserInfo.Result",
]

TELNET_SSH_PARAMS = [
    "InternetGatewayDevice.X_HW_CLITelnetAccess.Enable",
    "InternetGatewayDevice.X_HW_CLITelnetAccess.Port",
    "InternetGatewayDevice.X_HW_CLITelnetAccess.LanEnable",
    "InternetGatewayDevice.X_HW_CLISSHAccess.Enable",
    "InternetGatewayDevice.X_HW_CLISSHAccess.Port",
    "InternetGatewayDevice.X_HW_CLISSHAccess.LanEnable",
    "InternetGatewayDevice.X_HW_DEBUG.TelnetEnable",
    "InternetGatewayDevice.X_HW_DEBUG.SSHEnable",
]

# Extended WLAN params from actual router config
WIFI_PARAMS = [
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.PreSharedKey",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.KeyPassphrase",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.SSID",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey.1.PreSharedKey",
]

WIFI_FULL_PARAMS = [
    # 2.4GHz (instance 1)
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.Enable",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.BSSID",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.Channel",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.AutoChannelEnable",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.Standard",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.X_HW_Standard",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.TransmitPower",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.BeaconType",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.IEEE11iEncryptionModes",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.IEEE11iAuthenticationMode",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSIDAdvertisementEnabled",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.WMMEnable",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.MACAddressControlEnabled",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.PreSharedKey",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.KeyPassphrase",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.X_HW_RFBand",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.X_HW_Channel",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.X_HW_Band",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.X_HW_Powerlevel",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.X_HW_PowerValue",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.X_HW_AssociateNum",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.X_HW_GuardInterval",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.X_HW_RadiuServer",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.X_HW_RadiusPort",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.X_HW_RadiusKey",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.X_HW_GroupRekey",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.RegulatoryDomain",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.X_HW_OriginalSSID",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.X_HW_OriginalPassword",
    # WPS (instance 1)
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.WPS.Enable",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.WPS.DevicePassword",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.WPS.UUID",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.WPS.ConfigMethodsSupported",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.WPS.X_HW_ConfigMethod",
    # WEP keys (instance 1)
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.WEPKeyIndex",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.WEPEncryptionLevel",
    # 5GHz (instance 5 — Huawei convention)
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.Enable",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.SSID",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.BSSID",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.Channel",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.AutoChannelEnable",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.Standard",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.TransmitPower",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.BeaconType",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.IEEE11iEncryptionModes",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.SSIDAdvertisementEnabled",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey.1.PreSharedKey",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey.1.KeyPassphrase",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.X_HW_RFBand",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.X_HW_Channel",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.X_HW_Band",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.X_HW_Powerlevel",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.X_HW_OriginalSSID",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.X_HW_OriginalPassword",
    # Guest networks (instances 2, 3, 4 on 2.4GHz)
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.2.Enable",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.2.SSID",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.3.Enable",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.3.SSID",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.4.Enable",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.4.SSID",
]

GPON_PARAMS = [
    "InternetGatewayDevice.DeviceInfo.X_HW_OMCI.PLOAM_Password",
    "InternetGatewayDevice.DeviceInfo.X_HW_OMCI.LOID",
    "InternetGatewayDevice.DeviceInfo.X_HW_OMCI.LOIDPassword",
    "InternetGatewayDevice.DeviceInfo.X_HW_OMCI.OntSN",
]

WAN_PARAMS = [
    "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Username",
    "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Password",
    "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress",
]

VOIP_PARAMS = [
    "InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.1.Line.1.SIP.AuthUserName",
    "InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.1.Line.1.SIP.AuthPassword",
]

SECURITY_PARAMS = [
    "InternetGatewayDevice.X_HW_Security.Certificate.",
    "InternetGatewayDevice.X_HW_Security.Certificate.1.",
    "InternetGatewayDevice.X_HW_Security.AclServices.",
    "InternetGatewayDevice.X_HW_Security.Firewall.",
]

DNS_PARAMS = [
    "InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DNSServers",
]

HOST_PARAMS = [
    "InternetGatewayDevice.LANDevice.1.Hosts.Host.",
]

CERT_PARAMS = [
    "InternetGatewayDevice.X_HW_Security.Certificate.",
    "InternetGatewayDevice.X_HW_Security.Certificate.1.",
    "InternetGatewayDevice.ManagementServer.X_HW_Certificate",
    "InternetGatewayDevice.ManagementServer.X_HW_PrivateKey",
    "InternetGatewayDevice.ManagementServer.X_HW_CertPassword",
    "InternetGatewayDevice.UserInterface.X_HW_WebSslInfo.CertPassword",
]

SERVICE_PARAMS = [
    "InternetGatewayDevice.X_HW_ServiceManage.FtpEnable",
    "InternetGatewayDevice.X_HW_ServiceManage.FtpPort",
    "InternetGatewayDevice.X_HW_ServiceManage.FtpRoorDir",
]

SYSLOG_PARAMS = [
    "InternetGatewayDevice.DeviceInfo.X_HW_Syslog.Enable",
    "InternetGatewayDevice.DeviceInfo.X_HW_Syslog.Level",
    "InternetGatewayDevice.DeviceInfo.X_HW_SyslogConfig.LogServerEnable",
    "InternetGatewayDevice.DeviceInfo.X_HW_SyslogConfig.ServerAddress",
    "InternetGatewayDevice.DeviceInfo.X_HW_SyslogConfig.ServerPort",
]

POWER_MGMT_PARAMS = [
    "InternetGatewayDevice.X_HW_APMPolicy.EnablePowerSavingMode",
]

CREDENTIAL_PARAMS = (
    WEB_USER_PARAMS
    + MGMT_SERVER_PARAMS
    + WAN_PARAMS
    + VOIP_PARAMS
    + GPON_PARAMS
    + REMOTE_MGMT_PARAMS
    + USER_INFO_PARAMS
)

ALL_KNOWN_PARAMS = list(OrderedDict.fromkeys(
    DEVICE_INFO_PARAMS
    + PRODUCT_INFO_PARAMS
    + MGMT_SERVER_PARAMS
    + WEB_USER_PARAMS
    + REMOTE_MGMT_PARAMS
    + USER_INFO_PARAMS
    + TELNET_SSH_PARAMS
    + WIFI_PARAMS
    + GPON_PARAMS
    + WAN_PARAMS
    + VOIP_PARAMS
    + SECURITY_PARAMS
    + DNS_PARAMS
    + HOST_PARAMS
    + SERVICE_PARAMS
    + SYSLOG_PARAMS
    + POWER_MGMT_PARAMS
))

ALL_EXTENDED_PARAMS = list(OrderedDict.fromkeys(
    ALL_KNOWN_PARAMS + WIFI_FULL_PARAMS + CERT_PARAMS
))


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class DeviceInfo:
    """Information extracted from a CPE Inform message."""

    manufacturer: str = ""
    model_name: str = ""
    serial_number: str = ""
    product_class: str = ""
    oui: str = ""
    software_version: str = ""
    hardware_version: str = ""
    provisioning_code: str = ""
    connection_request_url: str = ""
    data_model: str = DataModel.TR098
    events: List[str] = field(default_factory=list)
    parameters: Dict[str, str] = field(default_factory=dict)
    raw_xml: str = ""


@dataclass
class CWMPSession:
    """State for a single CWMP session with a CPE."""

    session_id: str
    device: Optional[DeviceInfo] = None
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    rpc_queue: List[Tuple[str, Any]] = field(default_factory=list)
    results: List[RPCResult] = field(default_factory=list)
    inform_received: bool = False
    completed: bool = False


@dataclass
class RPCResult:
    """Result of a single RPC call."""

    method: str
    request_id: str = ""
    success: bool = False
    fault_code: str = ""
    fault_string: str = ""
    parameters: Dict[str, str] = field(default_factory=dict)
    status: int = 0
    raw_response: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ---------------------------------------------------------------------------
# CWMP methods
# ---------------------------------------------------------------------------

class CWMPMethod(Enum):
    """TR-069 CWMP RPC methods."""

    INFORM = auto()
    INFORM_RESPONSE = auto()
    GET_PARAMETER_VALUES = auto()
    GET_PARAMETER_VALUES_RESPONSE = auto()
    SET_PARAMETER_VALUES = auto()
    SET_PARAMETER_VALUES_RESPONSE = auto()
    GET_PARAMETER_NAMES = auto()
    GET_PARAMETER_NAMES_RESPONSE = auto()
    DOWNLOAD = auto()
    DOWNLOAD_RESPONSE = auto()
    REBOOT = auto()
    REBOOT_RESPONSE = auto()
    FACTORY_RESET = auto()
    FACTORY_RESET_RESPONSE = auto()
    ADD_OBJECT = auto()
    ADD_OBJECT_RESPONSE = auto()
    DELETE_OBJECT = auto()
    DELETE_OBJECT_RESPONSE = auto()
    FAULT = auto()
    EMPTY = auto()


# ---------------------------------------------------------------------------
# SOAP Builder – creates CWMP SOAP envelopes for ACS→CPE messages
# ---------------------------------------------------------------------------

class SOAPBuilder:
    """Build CWMP SOAP envelopes for each RPC method."""

    _id_counter: int = 0
    _lock = threading.Lock()

    @classmethod
    def _next_id(cls) -> str:
        with cls._lock:
            cls._id_counter += 1
            return str(cls._id_counter)

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _envelope(body_xml: str, request_id: str) -> str:
        return textwrap.dedent(f"""\
            <?xml version="1.0" encoding="UTF-8"?>
            <soapenv:Envelope
                xmlns:soapenv="{NS_SOAP_ENV}"
                xmlns:soapenc="{NS_SOAP_ENC}"
                xmlns:xsd="{NS_XSD}"
                xmlns:xsi="{NS_XSI}"
                xmlns:cwmp="{NS_CWMP}">
              <soapenv:Header>
                <cwmp:ID soapenv:mustUnderstand="1">{html.escape(request_id)}</cwmp:ID>
              </soapenv:Header>
              <soapenv:Body>
            {body_xml}
              </soapenv:Body>
            </soapenv:Envelope>""")

    # -- InformResponse ---------------------------------------------------

    @classmethod
    def inform_response(cls, request_id: str = "") -> Tuple[str, str]:
        rid = request_id or cls._next_id()
        body = "    <cwmp:InformResponse>\n      <MaxEnvelopes>1</MaxEnvelopes>\n    </cwmp:InformResponse>"
        return cls._envelope(body, rid), rid

    # -- GetParameterValues -----------------------------------------------

    @classmethod
    def get_parameter_values(
        cls, param_names: Sequence[str], request_id: str = "",
    ) -> Tuple[str, str]:
        rid = request_id or cls._next_id()
        names_xml = "\n".join(
            f'        <string>{html.escape(n)}</string>' for n in param_names
        )
        body = textwrap.dedent(f"""\
                <cwmp:GetParameterValues>
                  <ParameterNames soapenc:arrayType="xsd:string[{len(param_names)}]">
            {names_xml}
                  </ParameterNames>
                </cwmp:GetParameterValues>""")
        return cls._envelope(body, rid), rid

    # -- SetParameterValues -----------------------------------------------

    @classmethod
    def set_parameter_values(
        cls,
        params: Dict[str, Tuple[str, str]],
        parameter_key: str = "",
        request_id: str = "",
    ) -> Tuple[str, str]:
        """Build SetParameterValues.

        *params* maps parameter name → (value, xsd_type).
        ``xsd_type`` is e.g. ``"xsd:string"`` or ``"xsd:boolean"``.
        """
        rid = request_id or cls._next_id()
        entries: List[str] = []
        for name, (value, xsd_type) in params.items():
            entries.append(
                f"        <ParameterValueStruct>\n"
                f"          <Name>{html.escape(name)}</Name>\n"
                f'          <Value xsi:type="{html.escape(xsd_type)}">'
                f"{html.escape(str(value))}</Value>\n"
                f"        </ParameterValueStruct>"
            )
        plist = "\n".join(entries)
        body = textwrap.dedent(f"""\
                <cwmp:SetParameterValues>
                  <ParameterList soapenc:arrayType="cwmp:ParameterValueStruct[{len(params)}]">
            {plist}
                  </ParameterList>
                  <ParameterKey>{html.escape(parameter_key)}</ParameterKey>
                </cwmp:SetParameterValues>""")
        return cls._envelope(body, rid), rid

    # -- GetParameterNames ------------------------------------------------

    @classmethod
    def get_parameter_names(
        cls, parameter_path: str, next_level: bool = False, request_id: str = "",
    ) -> Tuple[str, str]:
        rid = request_id or cls._next_id()
        nl = "1" if next_level else "0"
        body = textwrap.dedent(f"""\
                <cwmp:GetParameterNames>
                  <ParameterPath>{html.escape(parameter_path)}</ParameterPath>
                  <NextLevel>{nl}</NextLevel>
                </cwmp:GetParameterNames>""")
        return cls._envelope(body, rid), rid

    # -- Download ---------------------------------------------------------

    @classmethod
    def download(
        cls,
        file_type: str,
        url: str,
        file_size: int = 0,
        target_filename: str = "",
        username: str = "",
        password: str = "",
        delay_seconds: int = 0,
        success_url: str = "",
        failure_url: str = "",
        request_id: str = "",
    ) -> Tuple[str, str]:
        rid = request_id or cls._next_id()
        body = textwrap.dedent(f"""\
                <cwmp:Download>
                  <CommandKey>{html.escape(rid)}</CommandKey>
                  <FileType>{html.escape(file_type)}</FileType>
                  <URL>{html.escape(url)}</URL>
                  <Username>{html.escape(username)}</Username>
                  <Password>{html.escape(password)}</Password>
                  <FileSize>{file_size}</FileSize>
                  <TargetFileName>{html.escape(target_filename)}</TargetFileName>
                  <DelaySeconds>{delay_seconds}</DelaySeconds>
                  <SuccessURL>{html.escape(success_url)}</SuccessURL>
                  <FailureURL>{html.escape(failure_url)}</FailureURL>
                </cwmp:Download>""")
        return cls._envelope(body, rid), rid

    # -- Reboot -----------------------------------------------------------

    @classmethod
    def reboot(cls, request_id: str = "") -> Tuple[str, str]:
        rid = request_id or cls._next_id()
        body = textwrap.dedent(f"""\
                <cwmp:Reboot>
                  <CommandKey>{html.escape(rid)}</CommandKey>
                </cwmp:Reboot>""")
        return cls._envelope(body, rid), rid

    # -- FactoryReset -----------------------------------------------------

    @classmethod
    def factory_reset(cls, request_id: str = "") -> Tuple[str, str]:
        rid = request_id or cls._next_id()
        body = "    <cwmp:FactoryReset />"
        return cls._envelope(body, rid), rid

    # -- AddObject --------------------------------------------------------

    @classmethod
    def add_object(
        cls, object_name: str, parameter_key: str = "", request_id: str = "",
    ) -> Tuple[str, str]:
        rid = request_id or cls._next_id()
        body = textwrap.dedent(f"""\
                <cwmp:AddObject>
                  <ObjectName>{html.escape(object_name)}</ObjectName>
                  <ParameterKey>{html.escape(parameter_key)}</ParameterKey>
                </cwmp:AddObject>""")
        return cls._envelope(body, rid), rid

    # -- DeleteObject -----------------------------------------------------

    @classmethod
    def delete_object(
        cls, object_name: str, parameter_key: str = "", request_id: str = "",
    ) -> Tuple[str, str]:
        rid = request_id or cls._next_id()
        body = textwrap.dedent(f"""\
                <cwmp:DeleteObject>
                  <ObjectName>{html.escape(object_name)}</ObjectName>
                  <ParameterKey>{html.escape(parameter_key)}</ParameterKey>
                </cwmp:DeleteObject>""")
        return cls._envelope(body, rid), rid


# ---------------------------------------------------------------------------
# SOAP Parser – parse CPE→ACS SOAP messages
# ---------------------------------------------------------------------------

class SOAPParser:
    """Parse CWMP SOAP messages received from the CPE."""

    @staticmethod
    def _find(root: ET.Element, path: str) -> Optional[ET.Element]:
        """Namespace-aware find helper."""
        parts = path.split("/")
        current = root
        for part in parts:
            found = None
            for child in current:
                tag = child.tag
                # strip namespace
                local = tag.rsplit("}", 1)[-1] if "}" in tag else tag
                if local == part:
                    found = child
                    break
            if found is None:
                return None
            current = found
        return current

    @staticmethod
    def _findall(root: ET.Element, local_name: str) -> List[ET.Element]:
        """Find all descendant elements with a given local name."""
        results: List[ET.Element] = []
        for elem in root.iter():
            tag = elem.tag
            local = tag.rsplit("}", 1)[-1] if "}" in tag else tag
            if local == local_name:
                results.append(elem)
        return results

    @staticmethod
    def _text(elem: Optional[ET.Element]) -> str:
        if elem is None:
            return ""
        return (elem.text or "").strip()

    @classmethod
    def detect_method(cls, xml_bytes: bytes) -> CWMPMethod:
        """Detect the CWMP method in a SOAP message."""
        try:
            root = ET.fromstring(xml_bytes)
        except ET.ParseError:
            return CWMPMethod.EMPTY

        body = cls._find(root, "Body")
        if body is None:
            return CWMPMethod.EMPTY

        for child in body:
            tag = child.tag
            local = tag.rsplit("}", 1)[-1] if "}" in tag else tag
            method_map = {
                "Inform": CWMPMethod.INFORM,
                "InformResponse": CWMPMethod.INFORM_RESPONSE,
                "GetParameterValuesResponse": CWMPMethod.GET_PARAMETER_VALUES_RESPONSE,
                "SetParameterValuesResponse": CWMPMethod.SET_PARAMETER_VALUES_RESPONSE,
                "GetParameterNamesResponse": CWMPMethod.GET_PARAMETER_NAMES_RESPONSE,
                "DownloadResponse": CWMPMethod.DOWNLOAD_RESPONSE,
                "RebootResponse": CWMPMethod.REBOOT_RESPONSE,
                "FactoryResetResponse": CWMPMethod.FACTORY_RESET_RESPONSE,
                "AddObjectResponse": CWMPMethod.ADD_OBJECT_RESPONSE,
                "DeleteObjectResponse": CWMPMethod.DELETE_OBJECT_RESPONSE,
                "Fault": CWMPMethod.FAULT,
                "GetParameterValues": CWMPMethod.GET_PARAMETER_VALUES,
                "SetParameterValues": CWMPMethod.SET_PARAMETER_VALUES,
                "GetParameterNames": CWMPMethod.GET_PARAMETER_NAMES,
                "Download": CWMPMethod.DOWNLOAD,
                "Reboot": CWMPMethod.REBOOT,
                "FactoryReset": CWMPMethod.FACTORY_RESET,
                "AddObject": CWMPMethod.ADD_OBJECT,
                "DeleteObject": CWMPMethod.DELETE_OBJECT,
            }
            if local in method_map:
                return method_map[local]

        return CWMPMethod.EMPTY

    @classmethod
    def parse_request_id(cls, xml_bytes: bytes) -> str:
        """Extract the CWMP ID from the SOAP header."""
        try:
            root = ET.fromstring(xml_bytes)
        except ET.ParseError:
            return ""
        header = cls._find(root, "Header")
        if header is None:
            return ""
        id_elem = cls._find(header, "ID")
        return cls._text(id_elem)

    @classmethod
    def parse_inform(cls, xml_bytes: bytes) -> DeviceInfo:
        """Parse a CPE Inform message."""
        device = DeviceInfo(raw_xml=xml_bytes.decode("utf-8", errors="replace"))
        try:
            root = ET.fromstring(xml_bytes)
        except ET.ParseError as exc:
            log.error("Failed to parse Inform XML: %s", exc)
            return device

        body = cls._find(root, "Body")
        if body is None:
            return device

        inform = cls._find(body, "Inform")
        if inform is None:
            return device

        # DeviceId
        dev_id = cls._find(inform, "DeviceId")
        if dev_id is not None:
            device.manufacturer = cls._text(cls._find(dev_id, "Manufacturer"))
            device.oui = cls._text(cls._find(dev_id, "OUI"))
            device.product_class = cls._text(cls._find(dev_id, "ProductClass"))
            device.serial_number = cls._text(cls._find(dev_id, "SerialNumber"))

        # Events
        for event_struct in cls._findall(inform, "EventStruct"):
            code_elem = cls._find(event_struct, "EventCode")
            code = cls._text(code_elem)
            if code:
                device.events.append(code)

        # ParameterList
        for pvs in cls._findall(inform, "ParameterValueStruct"):
            name_elem = cls._find(pvs, "Name")
            value_elem = cls._find(pvs, "Value")
            name = cls._text(name_elem)
            value = cls._text(value_elem)
            if name:
                device.parameters[name] = value
                # Populate fields from well-known params
                if name.endswith(".SoftwareVersion"):
                    device.software_version = value
                elif name.endswith(".HardwareVersion"):
                    device.hardware_version = value
                elif name.endswith(".ModelName"):
                    device.model_name = value
                elif name.endswith(".ProvisioningCode"):
                    device.provisioning_code = value
                elif name.endswith(".ConnectionRequestURL"):
                    device.connection_request_url = value

        # Auto-detect data model from parameter names
        device.data_model = DataModel.detect_from_inform(device.parameters)
        log.info("Detected data model: %s", device.data_model)

        return device

    @classmethod
    def parse_get_parameter_values_response(
        cls, xml_bytes: bytes,
    ) -> RPCResult:
        """Parse a GetParameterValuesResponse."""
        result = RPCResult(
            method="GetParameterValuesResponse",
            raw_response=xml_bytes.decode("utf-8", errors="replace"),
        )
        try:
            root = ET.fromstring(xml_bytes)
        except ET.ParseError as exc:
            result.fault_string = f"XML parse error: {exc}"
            return result

        result.request_id = cls.parse_request_id(xml_bytes)

        # Check for SOAP Fault
        fault = cls._check_fault(root)
        if fault:
            result.fault_code, result.fault_string = fault
            return result

        for pvs in cls._findall(root, "ParameterValueStruct"):
            name = cls._text(cls._find(pvs, "Name"))
            value = cls._text(cls._find(pvs, "Value"))
            if name:
                result.parameters[name] = value

        result.success = True
        return result

    @classmethod
    def parse_set_parameter_values_response(
        cls, xml_bytes: bytes,
    ) -> RPCResult:
        """Parse a SetParameterValuesResponse."""
        result = RPCResult(
            method="SetParameterValuesResponse",
            raw_response=xml_bytes.decode("utf-8", errors="replace"),
        )
        try:
            root = ET.fromstring(xml_bytes)
        except ET.ParseError as exc:
            result.fault_string = f"XML parse error: {exc}"
            return result

        result.request_id = cls.parse_request_id(xml_bytes)

        fault = cls._check_fault(root)
        if fault:
            result.fault_code, result.fault_string = fault
            return result

        # Status element (0 = applied, 1 = needs reboot)
        status_elem = cls._findall(root, "Status")
        if status_elem:
            try:
                result.status = int(cls._text(status_elem[0]))
            except ValueError:
                pass

        result.success = True
        return result

    @classmethod
    def parse_get_parameter_names_response(
        cls, xml_bytes: bytes,
    ) -> RPCResult:
        """Parse a GetParameterNamesResponse."""
        result = RPCResult(
            method="GetParameterNamesResponse",
            raw_response=xml_bytes.decode("utf-8", errors="replace"),
        )
        try:
            root = ET.fromstring(xml_bytes)
        except ET.ParseError as exc:
            result.fault_string = f"XML parse error: {exc}"
            return result

        result.request_id = cls.parse_request_id(xml_bytes)

        fault = cls._check_fault(root)
        if fault:
            result.fault_code, result.fault_string = fault
            return result

        for pis in cls._findall(root, "ParameterInfoStruct"):
            name = cls._text(cls._find(pis, "Name"))
            writable = cls._text(cls._find(pis, "Writable"))
            if name:
                result.parameters[name] = writable

        result.success = True
        return result

    @classmethod
    def parse_simple_response(cls, method_name: str, xml_bytes: bytes) -> RPCResult:
        """Parse a simple response (Reboot, FactoryReset, Download, Add/DeleteObject)."""
        result = RPCResult(
            method=method_name,
            raw_response=xml_bytes.decode("utf-8", errors="replace"),
        )
        try:
            root = ET.fromstring(xml_bytes)
        except ET.ParseError as exc:
            result.fault_string = f"XML parse error: {exc}"
            return result

        result.request_id = cls.parse_request_id(xml_bytes)

        fault = cls._check_fault(root)
        if fault:
            result.fault_code, result.fault_string = fault
            return result

        # Extract Status if present
        status_elems = cls._findall(root, "Status")
        if status_elems:
            try:
                result.status = int(cls._text(status_elems[0]))
            except ValueError:
                pass

        # Extract InstanceNumber for AddObjectResponse
        instance_elems = cls._findall(root, "InstanceNumber")
        if instance_elems:
            result.parameters["InstanceNumber"] = cls._text(instance_elems[0])

        result.success = True
        return result

    @classmethod
    def _check_fault(cls, root: ET.Element) -> Optional[Tuple[str, str]]:
        """Check for a SOAP Fault or CWMP Fault in the message."""
        # SOAP-level fault
        fault_elems = cls._findall(root, "Fault")
        if not fault_elems:
            return None

        for fault_elem in fault_elems:
            # CWMP fault inside detail
            fc = cls._find(fault_elem, "FaultCode")
            fs = cls._find(fault_elem, "FaultString")
            if fc is not None:
                return cls._text(fc), cls._text(fs)
            # Standard SOAP Fault
            fcode = cls._find(fault_elem, "faultcode")
            fstring = cls._find(fault_elem, "faultstring")
            if fcode is not None:
                return cls._text(fcode), cls._text(fstring)

        return None


# ---------------------------------------------------------------------------
# Session Manager
# ---------------------------------------------------------------------------

class SessionManager:
    """Track active CWMP sessions and queued RPCs."""

    def __init__(self) -> None:
        self._sessions: Dict[str, CWMPSession] = {}
        self._lock = threading.Lock()
        self._session_counter = 0

    def create_session(self) -> CWMPSession:
        with self._lock:
            self._session_counter += 1
            sid = f"ACS-{self._session_counter}-{int(time.time())}"
            session = CWMPSession(session_id=sid)
            self._sessions[sid] = session
            log.debug("Created session %s", sid)
            return session

    def get_session(self, session_id: str) -> Optional[CWMPSession]:
        with self._lock:
            return self._sessions.get(session_id)

    def get_or_create(self, cookie_header: str) -> Tuple[CWMPSession, bool]:
        """Find session from cookie or create a new one.

        Returns (session, is_new).
        """
        sid = self._parse_session_cookie(cookie_header)
        if sid:
            session = self.get_session(sid)
            if session is not None:
                session.last_activity = time.time()
                return session, False

        session = self.create_session()
        return session, True

    def remove_session(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)
            log.debug("Removed session %s", session_id)

    def list_sessions(self) -> List[CWMPSession]:
        with self._lock:
            return list(self._sessions.values())

    @staticmethod
    def _parse_session_cookie(cookie_header: str) -> str:
        if not cookie_header:
            return ""
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.startswith("CWMP_SESSIONID="):
                return part.split("=", 1)[1].strip()
        return ""


# ---------------------------------------------------------------------------
# Action Executor – pre-built actions for the Huawei HG8145V5
# ---------------------------------------------------------------------------

class ActionExecutor:
    """Execute pre-built actions (dump-config, enable-telnet, etc.)."""

    def __init__(self, listen_host: str, listen_port: int) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.detected_model: str = DataModel.TR098

    def get_acs_url(self) -> str:
        host = self.listen_host
        if host == "0.0.0.0":
            host = self._get_local_ip()
        return f"http://{host}:{self.listen_port}/"

    @staticmethod
    def _get_local_ip() -> str:
        """Best-effort detection of the local IP address."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("192.168.100.1", 80))
                return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"

    def _translate(self, paths: List[str]) -> List[str]:
        """Translate parameter paths for the detected data model."""
        return DataModel.translate_paths(paths, self.detected_model)

    def _translate_params(
        self, params: Dict[str, Tuple[str, str]],
    ) -> Dict[str, Tuple[str, str]]:
        """Translate SetParameterValues dict keys for detected data model."""
        if self.detected_model == DataModel.TR098:
            return params
        return {
            DataModel.to_tr181(k): v for k, v in params.items()
        }

    def build_rpc_queue(self, action: str) -> List[Tuple[str, Any]]:
        """Return a list of (method_tag, build_args) tuples for the action."""
        handlers = {
            "dump-config": self._action_dump_config,
            "dump-all": self._action_dump_all,
            "enable-telnet": self._action_enable_telnet,
            "enable-ssh": self._action_enable_ssh,
            "extract-creds": self._action_extract_creds,
            "extract-certs": self._action_extract_certs,
            "extract-wifi": self._action_extract_wifi,
            "extract-wifi-full": self._action_extract_wifi_full,
            "extract-gpon": self._action_extract_gpon,
            "extract-remote-mgmt": self._action_extract_remote_mgmt,
            "change-acs": self._action_change_acs,
            "change-dns": self._action_change_dns,
            "reboot": self._action_reboot,
            "factory-reset": self._action_factory_reset,
            "open-wan-mgmt": self._action_open_wan_mgmt,
        }
        handler = handlers.get(action)
        if handler is None:
            log.error("Unknown action: %s", action)
            return []
        return handler()

    # -- individual actions -----------------------------------------------

    def _action_dump_config(self) -> List[Tuple[str, Any]]:
        return [("GetParameterValues", self._translate(ALL_KNOWN_PARAMS))]

    def _action_dump_all(self) -> List[Tuple[str, Any]]:
        return [("GetParameterValues", self._translate(ALL_EXTENDED_PARAMS))]

    def _action_enable_telnet(self) -> List[Tuple[str, Any]]:
        params = {
            "InternetGatewayDevice.X_HW_CLITelnetAccess.Enable": ("true", "xsd:boolean"),
            "InternetGatewayDevice.X_HW_CLITelnetAccess.LanEnable": ("true", "xsd:boolean"),
            "InternetGatewayDevice.X_HW_CLITelnetAccess.Port": ("23", "xsd:unsignedInt"),
            "InternetGatewayDevice.X_HW_DEBUG.TelnetEnable": ("true", "xsd:boolean"),
        }
        return [("SetParameterValues", self._translate_params(params))]

    def _action_enable_ssh(self) -> List[Tuple[str, Any]]:
        params = {
            "InternetGatewayDevice.X_HW_CLISSHAccess.Enable": ("true", "xsd:boolean"),
            "InternetGatewayDevice.X_HW_CLISSHAccess.LanEnable": ("true", "xsd:boolean"),
            "InternetGatewayDevice.X_HW_CLISSHAccess.Port": ("22", "xsd:unsignedInt"),
            "InternetGatewayDevice.X_HW_DEBUG.SSHEnable": ("true", "xsd:boolean"),
        }
        return [("SetParameterValues", self._translate_params(params))]

    def _action_extract_creds(self) -> List[Tuple[str, Any]]:
        return [("GetParameterValues", self._translate(CREDENTIAL_PARAMS))]

    def _action_extract_certs(self) -> List[Tuple[str, Any]]:
        return [("GetParameterValues", self._translate(CERT_PARAMS))]

    def _action_extract_wifi(self) -> List[Tuple[str, Any]]:
        return [("GetParameterValues", self._translate(WIFI_PARAMS))]

    def _action_extract_wifi_full(self) -> List[Tuple[str, Any]]:
        return [("GetParameterValues", self._translate(WIFI_FULL_PARAMS))]

    def _action_extract_gpon(self) -> List[Tuple[str, Any]]:
        return [("GetParameterValues", self._translate(GPON_PARAMS))]

    def _action_extract_remote_mgmt(self) -> List[Tuple[str, Any]]:
        return [("GetParameterValues", self._translate(REMOTE_MGMT_PARAMS))]

    def _action_change_acs(self) -> List[Tuple[str, Any]]:
        acs_url = self.get_acs_url()
        acs_path = "InternetGatewayDevice.ManagementServer.URL"
        params = {acs_path: (acs_url, "xsd:string")}
        return [("SetParameterValues", self._translate_params(params))]

    def _action_change_dns(self) -> List[Tuple[str, Any]]:
        dns_path = "InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DNSServers"
        params = {dns_path: ("1.1.1.1,8.8.8.8", "xsd:string")}
        return [("SetParameterValues", self._translate_params(params))]

    def _action_reboot(self) -> List[Tuple[str, Any]]:
        return [("Reboot", None)]

    def _action_factory_reset(self) -> List[Tuple[str, Any]]:
        return [("FactoryReset", None)]

    def _action_open_wan_mgmt(self) -> List[Tuple[str, Any]]:
        params = {
            "InternetGatewayDevice.X_HW_CLITelnetAccess.Enable": ("true", "xsd:boolean"),
            "InternetGatewayDevice.X_HW_CLITelnetAccess.LanEnable": ("true", "xsd:boolean"),
            "InternetGatewayDevice.X_HW_CLISSHAccess.Enable": ("true", "xsd:boolean"),
            "InternetGatewayDevice.X_HW_CLISSHAccess.LanEnable": ("true", "xsd:boolean"),
            "InternetGatewayDevice.X_HW_DEBUG.TelnetEnable": ("true", "xsd:boolean"),
            "InternetGatewayDevice.X_HW_DEBUG.SSHEnable": ("true", "xsd:boolean"),
        }
        return [("SetParameterValues", self._translate_params(params))]


# ---------------------------------------------------------------------------
# HTTP Request Handler
# ---------------------------------------------------------------------------

class TR069Handler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for the TR-069 ACS.

    Handles the CWMP session flow:
      CPE Inform → InformResponse → RPC calls → empty POST (session end)
    """

    # Shared across instances; set by TR069Server before serving
    session_manager: SessionManager
    action_executor: ActionExecutor
    pending_action: Optional[str] = None
    result_event: Optional[threading.Event] = None
    collected_results: List[RPCResult] = []
    _results_lock = threading.Lock()

    # Silence default request logging (we log ourselves)
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D401
        """Route default HTTP request logging through the custom logger."""
        log.debug("HTTP: " + fmt, *args)

    # -- GET handler (keepalive / empty) -----------------------------------

    def do_GET(self) -> None:  # noqa: N802
        """Handle GET requests (typically keepalive or status check)."""
        log.debug("GET %s from %s", self.path, self.client_address)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>TR-069 ACS Active</h1></body></html>")

    # -- POST handler (SOAP envelopes) ------------------------------------

    def do_POST(self) -> None:  # noqa: N802
        """Handle POST requests carrying CWMP SOAP envelopes."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        cookie = self.headers.get("Cookie", "")
        session, is_new = self.session_manager.get_or_create(cookie)

        log.debug(
            "POST from %s, session=%s (new=%s), body_len=%d",
            self.client_address,
            session.session_id,
            is_new,
            len(body),
        )

        if body:
            log.debug("Request body:\n%s", body.decode("utf-8", errors="replace")[:2000])

        # Empty POST = CPE is asking for next RPC or ending session
        if not body or not body.strip():
            response_bytes = self._handle_empty_post(session)
        else:
            method = SOAPParser.detect_method(body)
            log.info(
                "Received %s from CPE [session=%s]",
                method.name,
                session.session_id,
            )
            response_bytes = self._dispatch(method, body, session)

        # Send response
        if response_bytes:
            self.send_response(200)
            self.send_header("Content-Type", 'text/xml; charset="utf-8"')
            self.send_header("Content-Length", str(len(response_bytes)))
            self.send_header(
                "Set-Cookie",
                f"CWMP_SESSIONID={session.session_id}; Path=/",
            )
            self.end_headers()
            self.wfile.write(response_bytes)
        else:
            # No more RPCs → 204 to end session
            self.send_response(204)
            self.send_header(
                "Set-Cookie",
                f"CWMP_SESSIONID={session.session_id}; Path=/",
            )
            self.end_headers()
            self._finalize_session(session)

    # -- Internal dispatch ------------------------------------------------

    def _dispatch(
        self, method: CWMPMethod, body: bytes, session: CWMPSession,
    ) -> Optional[bytes]:
        if method == CWMPMethod.INFORM:
            return self._handle_inform(body, session)
        elif method in (
            CWMPMethod.GET_PARAMETER_VALUES_RESPONSE,
            CWMPMethod.SET_PARAMETER_VALUES_RESPONSE,
            CWMPMethod.GET_PARAMETER_NAMES_RESPONSE,
            CWMPMethod.REBOOT_RESPONSE,
            CWMPMethod.FACTORY_RESET_RESPONSE,
            CWMPMethod.DOWNLOAD_RESPONSE,
            CWMPMethod.ADD_OBJECT_RESPONSE,
            CWMPMethod.DELETE_OBJECT_RESPONSE,
        ):
            return self._handle_rpc_response(method, body, session)
        elif method == CWMPMethod.FAULT:
            return self._handle_fault(body, session)
        else:
            log.warning("Unhandled method: %s", method.name)
            return self._next_rpc_envelope(session)

    # -- Inform -----------------------------------------------------------

    def _handle_inform(
        self, body: bytes, session: CWMPSession,
    ) -> Optional[bytes]:
        device = SOAPParser.parse_inform(body)
        session.device = device
        session.inform_received = True

        log.info(
            "CPE identified: %s %s (SN=%s, SW=%s, model=%s)",
            device.manufacturer,
            device.model_name or device.product_class,
            device.serial_number,
            device.software_version,
            device.data_model,
        )
        if device.events:
            log.info("  Events: %s", ", ".join(device.events))
        if device.connection_request_url:
            log.info("  ConnectionRequestURL: %s", device.connection_request_url)

        # Update action executor with detected data model
        self.action_executor.detected_model = device.data_model

        # Queue pending action RPCs into session
        if self.pending_action:
            rpcs = self.action_executor.build_rpc_queue(self.pending_action)
            session.rpc_queue.extend(rpcs)
            log.info(
                "Queued %d RPC(s) for action '%s'",
                len(rpcs),
                self.pending_action,
            )

        request_id = SOAPParser.parse_request_id(body)
        envelope, _ = SOAPBuilder.inform_response(request_id)
        return envelope.encode("utf-8")

    # -- RPC Response handling --------------------------------------------

    def _handle_rpc_response(
        self, method: CWMPMethod, body: bytes, session: CWMPSession,
    ) -> Optional[bytes]:
        result: RPCResult

        if method == CWMPMethod.GET_PARAMETER_VALUES_RESPONSE:
            result = SOAPParser.parse_get_parameter_values_response(body)
        elif method == CWMPMethod.SET_PARAMETER_VALUES_RESPONSE:
            result = SOAPParser.parse_set_parameter_values_response(body)
        elif method == CWMPMethod.GET_PARAMETER_NAMES_RESPONSE:
            result = SOAPParser.parse_get_parameter_names_response(body)
        else:
            result = SOAPParser.parse_simple_response(method.name, body)

        session.results.append(result)

        if result.success:
            log.info(
                "%s succeeded (params=%d)",
                result.method,
                len(result.parameters),
            )
            for name, value in result.parameters.items():
                log.debug("  %s = %s", name, value)
        else:
            log.warning(
                "%s failed: [%s] %s",
                result.method,
                result.fault_code,
                result.fault_string,
            )

        # Send next RPC or end session
        return self._next_rpc_envelope(session)

    # -- Fault handling ---------------------------------------------------

    def _handle_fault(
        self, body: bytes, session: CWMPSession,
    ) -> Optional[bytes]:
        result = RPCResult(
            method="Fault",
            raw_response=body.decode("utf-8", errors="replace"),
        )
        try:
            root = ET.fromstring(body)
            fault = SOAPParser._check_fault(root)
            if fault:
                result.fault_code, result.fault_string = fault
        except ET.ParseError:
            result.fault_string = "Unparseable fault"

        session.results.append(result)
        log.warning("SOAP Fault: [%s] %s", result.fault_code, result.fault_string)

        return self._next_rpc_envelope(session)

    # -- Empty POST (session continuation / end) --------------------------

    def _handle_empty_post(self, session: CWMPSession) -> Optional[bytes]:
        log.debug("Empty POST from CPE [session=%s]", session.session_id)
        return self._next_rpc_envelope(session)

    # -- Build and send next queued RPC -----------------------------------

    def _next_rpc_envelope(self, session: CWMPSession) -> Optional[bytes]:
        if not session.rpc_queue:
            log.info("No more RPCs queued – ending session %s", session.session_id)
            return None

        method_tag, args = session.rpc_queue.pop(0)
        log.info("Sending RPC: %s [session=%s]", method_tag, session.session_id)

        envelope: str
        if method_tag == "GetParameterValues":
            envelope, _ = SOAPBuilder.get_parameter_values(args)
        elif method_tag == "SetParameterValues":
            envelope, _ = SOAPBuilder.set_parameter_values(args)
        elif method_tag == "GetParameterNames":
            path, next_level = args
            envelope, _ = SOAPBuilder.get_parameter_names(path, next_level)
        elif method_tag == "Download":
            envelope, _ = SOAPBuilder.download(**args)
        elif method_tag == "Reboot":
            envelope, _ = SOAPBuilder.reboot()
        elif method_tag == "FactoryReset":
            envelope, _ = SOAPBuilder.factory_reset()
        elif method_tag == "AddObject":
            envelope, _ = SOAPBuilder.add_object(args)
        elif method_tag == "DeleteObject":
            envelope, _ = SOAPBuilder.delete_object(args)
        else:
            log.error("Unknown RPC method tag: %s", method_tag)
            return None

        return envelope.encode("utf-8")

    # -- Finalize session -------------------------------------------------

    def _finalize_session(self, session: CWMPSession) -> None:
        session.completed = True
        log.info(
            "Session %s completed with %d result(s)",
            session.session_id,
            len(session.results),
        )

        with self._results_lock:
            self.collected_results.extend(session.results)

        if self.result_event is not None:
            self.result_event.set()

        self.session_manager.remove_session(session.session_id)


# ---------------------------------------------------------------------------
# Connection Request – trigger CPE to connect to us
# ---------------------------------------------------------------------------

def send_connection_request(
    cpe_url: str,
    username: str = "",
    password: str = "",
    timeout: int = 10,
) -> bool:
    """Send an HTTP GET to the CPE's ConnectionRequestURL.

    Supports HTTP Digest authentication (RFC 7616) using stdlib only.
    Returns True if the CPE acknowledged the request (2xx).
    """
    parsed = urllib.parse.urlparse(cpe_url)
    host = parsed.hostname or "192.168.100.1"
    port = parsed.port or 80
    path = parsed.path or "/"

    log.info("Sending connection request to %s", cpe_url)

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            request_line = f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
            sock.sendall(request_line.encode())
            response = sock.recv(4096).decode("utf-8", errors="replace")
            log.debug("Connection request response:\n%s", response[:500])

            status_match = re.match(r"HTTP/\d\.\d (\d+)", response)
            if not status_match:
                log.error("Invalid HTTP response from CPE")
                return False

            status_code = int(status_match.group(1))

            if status_code == 401 and username:
                # HTTP Digest Auth
                return _digest_auth_request(
                    host, port, path, username, password, response, timeout,
                )

            if 200 <= status_code < 300:
                log.info("Connection request accepted (HTTP %d)", status_code)
                return True

            log.warning("Connection request returned HTTP %d", status_code)
            return False

    except OSError as exc:
        log.error("Connection request failed: %s", exc)
        return False


def _digest_auth_request(
    host: str,
    port: int,
    path: str,
    username: str,
    password: str,
    initial_response: str,
    timeout: int,
) -> bool:
    """Perform HTTP Digest authentication for a connection request."""
    # Parse WWW-Authenticate header
    auth_match = re.search(
        r'WWW-Authenticate:\s*Digest\s+(.*)', initial_response, re.IGNORECASE,
    )
    if not auth_match:
        log.error("No Digest challenge in 401 response")
        return False

    challenge = auth_match.group(1)
    params: Dict[str, str] = {}
    for m in re.finditer(r'(\w+)=(?:"([^"]+)"|([^\s,]+))', challenge):
        params[m.group(1)] = m.group(2) or m.group(3)

    realm = params.get("realm", "")
    nonce = params.get("nonce", "")
    qop = params.get("qop", "")

    # Compute digest
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"GET:{path}".encode()).hexdigest()

    if "auth" in qop:
        nc = "00000001"
        cnonce = hashlib.md5(str(time.time()).encode()).hexdigest()[:16]
        response_hash = hashlib.md5(
            f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}".encode(),
        ).hexdigest()
        auth_header = (
            f'Digest username="{username}", realm="{realm}", '
            f'nonce="{nonce}", uri="{path}", qop=auth, nc={nc}, '
            f'cnonce="{cnonce}", response="{response_hash}"'
        )
    else:
        response_hash = hashlib.md5(
            f"{ha1}:{nonce}:{ha2}".encode(),
        ).hexdigest()
        auth_header = (
            f'Digest username="{username}", realm="{realm}", '
            f'nonce="{nonce}", uri="{path}", response="{response_hash}"'
        )

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            request_line = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.sendall(request_line.encode())
            response = sock.recv(4096).decode("utf-8", errors="replace")
            status_match = re.match(r"HTTP/\d\.\d (\d+)", response)
            if status_match:
                code = int(status_match.group(1))
                if 200 <= code < 300:
                    log.info("Digest auth connection request accepted (HTTP %d)", code)
                    return True
                log.warning("Digest auth returned HTTP %d", code)
            return False
    except OSError as exc:
        log.error("Digest auth connection request failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# TR-069 ACS Server
# ---------------------------------------------------------------------------

class TR069Server:
    """Main ACS server.  Binds HTTP, manages sessions, executes actions."""

    def __init__(
        self,
        listen: str = "0.0.0.0",
        port: int = 7547,
        action: Optional[str] = None,
        cpe_url: Optional[str] = None,
        output: Optional[str] = None,
        log_file: Optional[str] = None,
        cpe_username: str = "",
        cpe_password: str = "",
    ) -> None:
        self.listen = listen
        self.port = port
        self.action = action
        self.cpe_url = cpe_url
        self.output = output
        self.cpe_username = cpe_username
        self.cpe_password = cpe_password

        self.session_manager = SessionManager()
        self.action_executor = ActionExecutor(listen, port)

        # Configure file logging if requested
        if log_file:
            fh = logging.FileHandler(log_file)
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            ))
            logging.getLogger().addHandler(fh)

        # Result signalling for action mode
        self.result_event = threading.Event()
        self.collected_results: List[RPCResult] = []

        # Configure the handler class
        TR069Handler.session_manager = self.session_manager
        TR069Handler.action_executor = self.action_executor
        TR069Handler.pending_action = self.action
        TR069Handler.result_event = self.result_event
        TR069Handler.collected_results = self.collected_results

    def run(self) -> None:
        """Start the ACS server."""
        server = http.server.HTTPServer(
            (self.listen, self.port), TR069Handler,
        )
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        log.info("TR-069 ACS listening on %s:%d", self.listen, self.port)

        if self.action:
            log.info("Action mode: '%s'", self.action)
            log.info(
                "Waiting for CPE to connect (or trigger via --cpe-url)...",
            )

            # Optionally trigger CPE connection
            if self.cpe_url:
                trigger_thread = threading.Thread(
                    target=self._trigger_connection, daemon=True,
                )
                trigger_thread.start()

            # Wait for results with timeout
            if self.result_event.wait(timeout=300):
                self._save_results()
            else:
                log.error(
                    "Timeout waiting for CPE session to complete "
                    "(300s elapsed)",
                )
                sys.exit(1)

            server.shutdown()
        else:
            log.info("Interactive mode – press Ctrl+C to stop")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                log.info("Shutting down...")
                server.shutdown()

    def _trigger_connection(self) -> None:
        """Send a connection request to the CPE after a short delay."""
        time.sleep(1)
        send_connection_request(
            self.cpe_url or "",
            username=self.cpe_username,
            password=self.cpe_password,
        )

    def _save_results(self) -> None:
        """Save collected RPC results to JSON."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        output_path = self.output or f"tr069_results_{timestamp}.json"

        # Build output document
        doc: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": self.action,
            "acs_url": self.action_executor.get_acs_url(),
            "results": [],
        }

        all_params: Dict[str, str] = {}

        for result in self.collected_results:
            entry: Dict[str, Any] = {
                "method": result.method,
                "success": result.success,
                "timestamp": result.timestamp,
            }
            if result.fault_code:
                entry["fault_code"] = result.fault_code
                entry["fault_string"] = result.fault_string
            if result.parameters:
                entry["parameters"] = result.parameters
                all_params.update(result.parameters)
            if result.status:
                entry["status"] = result.status
            doc["results"].append(entry)

        if all_params:
            doc["all_parameters"] = dict(sorted(all_params.items()))

        path = Path(output_path)
        path.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
        log.info("Results saved to %s", path)
        log.info("Extracted %d parameter(s)", len(all_params))

        # Print summary to stdout
        if all_params:
            print(f"\n{'=' * 60}")
            print(f" TR-069 Results – {self.action}")
            print(f"{'=' * 60}")
            for name in sorted(all_params):
                print(f"  {name} = {all_params[name]}")
            print(f"{'=' * 60}")
            print(f"  Total: {len(all_params)} parameter(s)")
            print(f"  Saved to: {path}")
            print(f"{'=' * 60}\n")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

VALID_ACTIONS = [
    "dump-config",
    "dump-all",
    "enable-telnet",
    "enable-ssh",
    "extract-creds",
    "extract-certs",
    "extract-wifi",
    "extract-wifi-full",
    "extract-gpon",
    "extract-remote-mgmt",
    "change-acs",
    "change-dns",
    "reboot",
    "factory-reset",
    "open-wan-mgmt",
]


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "TR-069 ACS (Auto Configuration Server) for "
            "Huawei HG8145V5 Router Management"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              # Start ACS and wait for CPE
              python tools/tr069_server.py --listen 0.0.0.0 --port 7547

              # Dump full config (all extended params incl. WiFi, WPS, certs)
              python tools/tr069_server.py --action dump-all --output config.json

              # Enable Telnet, trigger CPE connection
              python tools/tr069_server.py --action enable-telnet \\
                  --cpe-url http://192.168.100.1:7547/

              # Extract WiFi credentials (full: both bands, WPS, guests)
              python tools/tr069_server.py --action extract-wifi-full --output wifi.json

              # Extract remote management credentials
              python tools/tr069_server.py --action extract-remote-mgmt

            supported actions:
              dump-config          Dump standard TR-069 parameters to JSON
              dump-all             Dump ALL known parameters (extended WiFi, certs, etc.)
              enable-telnet        Enable Telnet on LAN side
              enable-ssh           Enable SSH on LAN side
              extract-creds        Extract all stored credentials
              extract-certs        Extract certificates, private keys, cert passwords
              extract-wifi         Extract WiFi SSID and PSK (basic)
              extract-wifi-full    Extract full WiFi config (both bands, WPS, guests)
              extract-gpon         Extract GPON/ONT parameters
              extract-remote-mgmt  Extract X_HW_AppRemoteManage credentials
              change-acs           Redirect ACS URL to this server
              change-dns           Change DNS servers to 1.1.1.1, 8.8.8.8
              reboot               Reboot the device
              factory-reset        Factory reset the device
              open-wan-mgmt        Enable WAN-side management (HTTP/Telnet/SSH)

            data model support:
              The server auto-detects whether the CPE uses TR-098
              (InternetGatewayDevice.) or TR-181 (Device.) parameter paths
              from the Inform message.  Parameter paths are translated
              automatically.

            MEGACABLE ISP info (from router config):
              ACS URL:   %(acs_url)s
              Username:  %(acs_user)s
              ConnReq:   %(conn_user)s
              Firmware:  %(firmware)s
        """ % {
            "acs_url": MEGACABLE_ISP_CONFIG["acs_url"],
            "acs_user": MEGACABLE_ISP_CONFIG["acs_username"],
            "conn_user": MEGACABLE_ISP_CONFIG["conn_req_username"],
            "firmware": MEGACABLE_ISP_CONFIG["firmware_original"],
        }),
    )
    parser.add_argument(
        "--listen",
        default="0.0.0.0",
        help="Address to bind the ACS HTTP server (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=7547,
        help="Port to bind the ACS HTTP server (default: 7547)",
    )
    parser.add_argument(
        "--action",
        choices=VALID_ACTIONS,
        default=None,
        help="Pre-built action to execute when CPE connects",
    )
    parser.add_argument(
        "--cpe-url",
        default=None,
        help="CPE ConnectionRequestURL to trigger a session",
    )
    parser.add_argument(
        "--cpe-username",
        default="",
        help="Username for CPE connection request auth",
    )
    parser.add_argument(
        "--cpe-password",
        default="",
        help="Password for CPE connection request auth",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output file path for results JSON",
    )
    parser.add_argument(
        "--log-file",
        default=None,
        help="Write logs to this file in addition to stderr",
    )

    args = parser.parse_args()

    server = TR069Server(
        listen=args.listen,
        port=args.port,
        action=args.action,
        cpe_url=args.cpe_url,
        output=args.output,
        log_file=args.log_file,
        cpe_username=args.cpe_username,
        cpe_password=args.cpe_password,
    )
    server.run()


if __name__ == "__main__":
    main()
