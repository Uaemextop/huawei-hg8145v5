"""
Security audit tool for the Huawei HG8145V5 router web interface.

Probes the router for known vulnerabilities discovered through client-side
code analysis.  Each check is independent and reports PASS / FAIL / SKIP.

Usage:
    python -m tools.security_audit --host 192.168.100.1
    python tools/security_audit.py --host 192.168.100.1 --user Mega_gpon --password <pw>

All checks run over HTTP only; this tool never modifies the router config.
Read-only probes only.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import requests
import urllib3

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("security_audit")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
REQUEST_TIMEOUT = 10

# Known pre-login endpoints (no authentication required)
PRE_LOGIN_ENDPOINTS = [
    "/index.asp",
    "/login.asp",
    "/asp/GetRandCount.asp",
    "/html/ssmp/common/getRandString.asp",
    "/asp/CheckPwdNotLogin.asp",
    "/asp/GetRandInfo.asp",
]

# Known post-login endpoints
POST_LOGIN_ENDPOINTS = [
    "/getajax.cgi",
    "/html/ssmp/common/GetRandToken.asp",
    "/html/ssmp/common/StartFileLoad.asp",
]

# CGI endpoints discovered from index.asp
CGI_ENDPOINTS = [
    "/login.cgi",
    "/logout.cgi",
    "/FrameModeSwitch.cgi",
    "/MdfPwdNormalNoLg.cgi",
    "/MdfPwdAdminNoLg.cgi",
    "/getCheckCode.cgi",
    "/getajax.cgi",
]

# TR-069 object paths to probe for sensitive data
TR069_PATHS = [
    "InternetGatewayDevice.DeviceInfo.",
    "InternetGatewayDevice.UserInterface.",
    "InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.1.",
    "InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.2.",
    "InternetGatewayDevice.ManagementServer.",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.",
    "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.",
    "InternetGatewayDevice.Services.",
    "InternetGatewayDevice.Layer3Forwarding.",
    "InternetGatewayDevice.X_HW_CLITelnetAccess.",
    "InternetGatewayDevice.X_HW_CLISSHAccess.",
    "InternetGatewayDevice.X_HW_DEBUG.",
    "InternetGatewayDevice.IPPingDiagnostics.",
]

# TR-069 paths for certificate, key, and credential extraction (V-25)
TR069_SENSITIVE_PATHS = [
    # Certificates and private keys
    ("InternetGatewayDevice.X_HW_Security.Certificate.", "TLS certificates"),
    ("InternetGatewayDevice.X_HW_Security.Certificate.1.", "First certificate"),
    ("InternetGatewayDevice.ManagementServer.X_HW_Certificate", "ACS client cert"),
    ("InternetGatewayDevice.ManagementServer.X_HW_PrivateKey", "ACS private key"),
    # Stored credentials
    ("InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.1.Password", "Web user password"),
    ("InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.2.Password", "Web admin password"),
    ("InternetGatewayDevice.ManagementServer.Username", "ACS username"),
    ("InternetGatewayDevice.ManagementServer.Password", "ACS password"),
    ("InternetGatewayDevice.ManagementServer.ConnectionRequestPassword", "Conn req password"),
    ("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Password",
     "PPPoE password"),
    ("InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.1.Line.1.SIP.AuthPassword",
     "VoIP SIP password"),
    # WiFi keys
    ("InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.PreSharedKey",
     "WiFi 2.4GHz PSK"),
    ("InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.KeyPassphrase",
     "WiFi 2.4GHz passphrase"),
    ("InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey.1.PreSharedKey",
     "WiFi 5GHz PSK"),
    # GPON/ONT parameters
    ("InternetGatewayDevice.DeviceInfo.X_HW_OMCI.PLOAM_Password", "GPON PLOAM password"),
    ("InternetGatewayDevice.DeviceInfo.X_HW_OMCI.LOID", "GPON LOID"),
    ("InternetGatewayDevice.DeviceInfo.X_HW_OMCI.LOIDPassword", "GPON LOID password"),
    ("InternetGatewayDevice.DeviceInfo.X_HW_OMCI.OntSN", "ONT serial number"),
    # Security and ACL
    ("InternetGatewayDevice.X_HW_Security.", "Security config"),
    ("InternetGatewayDevice.X_HW_Security.AclServices.", "ACL services"),
    ("InternetGatewayDevice.X_HW_Security.Firewall.", "Firewall rules"),
    # Connected devices
    ("InternetGatewayDevice.LANDevice.1.Hosts.Host.", "Connected devices table"),
]

# Server variables leaked in index.asp
LEAKED_VARS_PATTERNS = [
    (r"var\s+CfgMode\s*=\s*'([^']*)'", "CfgMode"),
    (r"var\s+ProductName\s*=\s*'([^']*)'", "ProductName"),
    (r"var\s+ProductType\s*=\s*'([^']*)'", "ProductType"),
    (r"var\s+Userlevel\s*=\s*(\d+)", "Userlevel"),
    (r"var\s+defaultUsername\s*=\s*'([^']*)'", "defaultUsername"),
    (r"var\s+defaultPassword\s*=\s*'([^']*)'", "defaultPassword"),
    (r"var\s+errloginlockNum\s*=\s*'([^']*)'", "errloginlockNum"),
    (r"var\s+useChallengeCode\s*=\s*'([^']*)'", "useChallengeCode"),
    (r"var\s+randcode\s*=\s*'([^']*)'", "randcode"),
    (r"var\s+APPVersion\s*=\s*'([^']*)'", "APPVersion"),
    (r"var\s+Ssid1\s*=\s*'([^']*)'", "Ssid1"),
    (r"var\s+Ssid2\s*=\s*'([^']*)'", "Ssid2"),
    (r"var\s+languageList\s*=\s*'([^']*)'", "languageList"),
    (r"var\s+mngttype\s*=\s*'([^']*)'", "mngttype"),
]

LOGIN_MARKERS = ("txt_Username", "txt_Password", "loginbutton")


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------
@dataclass
class CheckResult:
    """Result of a single security check."""
    check_id: str
    title: str
    status: str          # "VULN", "OK", "SKIP", "ERROR"
    severity: str        # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    details: str = ""
    data: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Audit class
# ---------------------------------------------------------------------------
class SecurityAudit:
    """Run all security checks against the router."""

    def __init__(
        self,
        host: str,
        username: str | None = None,
        password: str | None = None,
        verify_ssl: bool = True,
    ):
        self.host = host
        self.base = f"http://{host}"
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.results: list[CheckResult] = []
        self._login_page_text: str | None = None
        self._pre_login_token: str | None = None
        self._is_logged_in = False

    # ---------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------
    def _get(self, path: str, **kwargs) -> requests.Response | None:
        try:
            return self.session.get(
                self.base + path, timeout=REQUEST_TIMEOUT, **kwargs
            )
        except requests.RequestException as e:
            log.debug("GET %s failed: %s", path, e)
            return None

    def _post(self, path: str, **kwargs) -> requests.Response | None:
        try:
            return self.session.post(
                self.base + path, timeout=REQUEST_TIMEOUT, **kwargs
            )
        except requests.RequestException as e:
            log.debug("POST %s failed: %s", path, e)
            return None

    def _fetch_login_page(self) -> str | None:
        """Fetch and cache the login page HTML."""
        if self._login_page_text is not None:
            return self._login_page_text
        resp = self._get("/index.asp")
        if resp and resp.ok:
            self._login_page_text = resp.text
            return self._login_page_text
        return None

    def _fetch_pre_login_token(self) -> str | None:
        """Fetch a pre-login anti-CSRF token."""
        if self._pre_login_token is not None:
            return self._pre_login_token
        resp = self._post("/html/ssmp/common/getRandString.asp")
        if resp and resp.ok:
            token = resp.text.strip()
            if token and len(token) >= 8:
                self._pre_login_token = token
                return token
        return None

    def _login(self) -> bool:
        """Attempt to log in and return True on success."""
        if not self.username or not self.password:
            return False
        if self._is_logged_in:
            return True

        # Set pre-login cookie
        self.session.cookies.clear()
        self.session.cookies.set("Cookie", "body:Language:english:id=-1", path="/")

        # Get CSRF token
        resp = self._post("/asp/GetRandCount.asp")
        if not resp or not resp.ok:
            return False
        token = resp.text.strip()

        # Submit login
        encoded_pw = base64.b64encode(self.password.encode()).decode()
        resp = self._post(
            "/login.cgi",
            data={
                "UserName": self.username,
                "PassWord": encoded_pw,
                "Language": "english",
                "x.X_HW_Token": token,
            },
            allow_redirects=True,
        )
        if not resp:
            return False

        # Check for login form markers
        if all(m in resp.text for m in LOGIN_MARKERS):
            return False

        # Follow JS redirect
        self.session.headers["Referer"] = self.base + "/"
        self._is_logged_in = True
        return True

    def _add(self, result: CheckResult) -> None:
        self.results.append(result)
        icon = {"VULN": "⚠️", "OK": "✅", "SKIP": "⏭️", "ERROR": "❌"}.get(
            result.status, "?"
        )
        log.info(
            "%s [%s] %s: %s – %s",
            icon,
            result.severity,
            result.check_id,
            result.title,
            result.details or result.status,
        )

    # ---------------------------------------------------------------
    # Individual checks
    # ---------------------------------------------------------------
    def check_v01_base64_password(self) -> None:
        """V-01: Check if password is sent as reversible Base64."""
        page = self._fetch_login_page()
        if not page:
            self._add(CheckResult("V-01", "Base64 password encoding",
                                  "SKIP", "HIGH", "Could not fetch login page"))
            return

        if "base64encode(Password.value)" in page:
            self._add(CheckResult(
                "V-01", "Base64 password encoding", "VULN", "HIGH",
                "Login page uses base64encode() on password — trivially reversible",
            ))
        else:
            self._add(CheckResult("V-01", "Base64 password encoding",
                                  "OK", "HIGH", "base64encode pattern not found"))

    def check_v02_prelogin_token(self) -> None:
        """V-02: Check if pre-login token endpoint is accessible."""
        resp = self._post("/html/ssmp/common/getRandString.asp")
        if resp and resp.ok and len(resp.text.strip()) >= 8:
            self._add(CheckResult(
                "V-02", "Pre-login token accessible", "VULN", "MEDIUM",
                f"getRandString.asp returns token ({len(resp.text.strip())} chars) without auth",
                data={"token_length": len(resp.text.strip())},
            ))
        else:
            self._add(CheckResult("V-02", "Pre-login token accessible",
                                  "OK", "MEDIUM",
                                  "Token endpoint not accessible or returned empty"))

    def check_v03_password_oracle(self) -> None:
        """V-03: Check if CheckPwdNotLogin.asp exists and responds."""
        resp = self._post(
            "/asp/CheckPwdNotLogin.asp",
            params={"1": "1"},
            data={"UserNameInfo": "test", "NormalPwdInfo": "test"},
        )
        if resp and resp.ok:
            self._add(CheckResult(
                "V-03", "Pre-login password oracle", "VULN", "HIGH",
                f"CheckPwdNotLogin.asp responds (HTTP {resp.status_code}, "
                f"body={resp.text[:100]!r})",
                data={"response": resp.text[:200]},
            ))
        elif resp and resp.status_code in (403, 404):
            self._add(CheckResult(
                "V-03", "Pre-login password oracle", "OK", "HIGH",
                f"Endpoint returns HTTP {resp.status_code}",
            ))
        else:
            self._add(CheckResult("V-03", "Pre-login password oracle",
                                  "SKIP", "HIGH", "Could not reach endpoint"))

    def check_v04_csrf_token(self) -> None:
        """V-04: Check anti-CSRF token strength."""
        resp = self._post("/asp/GetRandCount.asp")
        if resp and resp.ok:
            token = resp.text.strip()
            self._add(CheckResult(
                "V-04", "CSRF token analysis", "VULN", "MEDIUM",
                f"GetRandCount.asp returns token without auth "
                f"(len={len(token)}, hex={'yes' if all(c in '0123456789abcdef' for c in token) else 'no'})",
                data={"token": token[:24] + "...", "length": len(token)},
            ))
        else:
            self._add(CheckResult("V-04", "CSRF token analysis",
                                  "SKIP", "MEDIUM", "Could not fetch token"))

    def check_v05_eval_in_code(self) -> None:
        """V-05: Check for dealDataWithFun (eval) in client code."""
        page = self._fetch_login_page()
        if not page:
            self._add(CheckResult("V-05", "JavaScript eval() pattern",
                                  "SKIP", "CRITICAL",
                                  "Could not fetch login page"))
            return

        count = page.count("dealDataWithFun")
        if count > 0:
            self._add(CheckResult(
                "V-05", "JavaScript eval() pattern", "VULN", "CRITICAL",
                f"dealDataWithFun() found {count} time(s) in login page — "
                "executes arbitrary server responses as code",
                data={"occurrences": count},
            ))
        else:
            self._add(CheckResult("V-05", "JavaScript eval() pattern",
                                  "OK", "CRITICAL",
                                  "dealDataWithFun pattern not found"))

    def check_v06_cookie_attributes(self) -> None:
        """V-06: Check session cookie security attributes."""
        page = self._fetch_login_page()
        if not page:
            self._add(CheckResult("V-06", "Cookie security attributes",
                                  "SKIP", "MEDIUM",
                                  "Could not fetch login page"))
            return

        issues = []
        if 'Cookie=body:' in page:
            issues.append("Cookie name is 'Cookie' (confusing)")
        if 'Secure' not in page and 'secure' not in page:
            issues.append("No Secure flag")
        if 'HttpOnly' not in page and 'httponly' not in page:
            issues.append("No HttpOnly flag")
        if 'SameSite' not in page and 'samesite' not in page:
            issues.append("No SameSite attribute")

        if issues:
            self._add(CheckResult(
                "V-06", "Cookie security attributes", "VULN", "MEDIUM",
                "; ".join(issues),
                data={"issues": issues},
            ))
        else:
            self._add(CheckResult("V-06", "Cookie security attributes",
                                  "OK", "MEDIUM", "Cookie attributes look OK"))

    def check_v07_framemode_switch(self) -> None:
        """V-07: Check if FrameModeSwitch.cgi is accessible pre-auth."""
        # We only probe with GET to avoid modifying the device
        resp = self._get("/FrameModeSwitch.cgi")
        if resp and resp.status_code != 404:
            self._add(CheckResult(
                "V-07", "FrameModeSwitch.cgi accessible", "VULN", "HIGH",
                f"Endpoint responds with HTTP {resp.status_code} "
                "(may accept unauthenticated POSTs)",
                data={"status_code": resp.status_code},
            ))
        else:
            self._add(CheckResult("V-07", "FrameModeSwitch.cgi accessible",
                                  "OK", "HIGH",
                                  "Endpoint not found or returns 404"))

    def check_v08_tr069_paths(self) -> None:
        """V-08: Probe TR-069 object paths via getajax.cgi (requires auth)."""
        if not self._is_logged_in:
            if not self._login():
                self._add(CheckResult(
                    "V-08", "TR-069 path traversal", "SKIP", "HIGH",
                    "Login required but credentials not provided or login failed",
                ))
                return

        accessible = []
        for objpath in TR069_PATHS:
            resp = self._post(f"/getajax.cgi?{objpath}")
            if resp and resp.ok and len(resp.text.strip()) > 10:
                # Check for actual data (not just error)
                text = resp.text.strip()
                if "error" not in text.lower() and text != "{ }":
                    accessible.append(objpath)
                    log.debug("  TR-069 %s → %s", objpath, text[:80])

        if accessible:
            self._add(CheckResult(
                "V-08", "TR-069 path traversal", "VULN", "HIGH",
                f"{len(accessible)}/{len(TR069_PATHS)} TR-069 paths returned data",
                data={"accessible_paths": accessible},
            ))
        else:
            self._add(CheckResult("V-08", "TR-069 path traversal",
                                  "OK", "HIGH",
                                  "No TR-069 paths returned useful data"))

    def check_v09_noauth_password_change(self) -> None:
        """V-09: Check if MdfPwd*NoLg.cgi endpoints exist."""
        for endpoint in ("/MdfPwdNormalNoLg.cgi", "/MdfPwdAdminNoLg.cgi"):
            resp = self._get(endpoint)
            if resp and resp.status_code != 404:
                self._add(CheckResult(
                    "V-09", f"No-login password change ({endpoint})",
                    "VULN", "CRITICAL",
                    f"{endpoint} responds with HTTP {resp.status_code}",
                    data={"endpoint": endpoint, "status_code": resp.status_code},
                ))
            else:
                self._add(CheckResult(
                    "V-09", f"No-login password change ({endpoint})",
                    "OK", "CRITICAL",
                    f"{endpoint} returns 404",
                ))

    def check_v10_leaked_variables(self) -> None:
        """V-10: Check for leaked server variables in login page."""
        page = self._fetch_login_page()
        if not page:
            self._add(CheckResult("V-10", "Server variable leakage",
                                  "SKIP", "LOW",
                                  "Could not fetch login page"))
            return

        leaked = {}
        for pattern, name in LEAKED_VARS_PATTERNS:
            m = re.search(pattern, page)
            if m:
                value = m.group(1)
                if value:  # Only report non-empty values
                    leaked[name] = value

        critical_leaks = []
        if leaked.get("defaultUsername"):
            critical_leaks.append(f"defaultUsername={leaked['defaultUsername']}")
        if leaked.get("defaultPassword"):
            critical_leaks.append(f"defaultPassword=***")

        severity = "HIGH" if critical_leaks else ("MEDIUM" if leaked else "LOW")
        status = "VULN" if leaked else "OK"

        details = f"{len(leaked)} variables leaked"
        if critical_leaks:
            details += f" (CRITICAL: {', '.join(critical_leaks)})"

        self._add(CheckResult(
            "V-10", "Server variable leakage", status, severity,
            details, data={"leaked": leaked},
        ))

    def check_v11_login_rate_limit(self) -> None:
        """V-11: Check if login has server-side rate limiting."""
        page = self._fetch_login_page()
        if not page:
            self._add(CheckResult("V-11", "Login rate limiting",
                                  "SKIP", "MEDIUM",
                                  "Could not fetch login page"))
            return

        m = re.search(r"var\s+errloginlockNum\s*=\s*'(\d+)'", page)
        lockout = m.group(1) if m else "unknown"

        if "errloginlockNum" in page and "LockLeftTime" in page:
            self._add(CheckResult(
                "V-11", "Login rate limiting", "VULN", "MEDIUM",
                f"Client-side lockout after {lockout} attempts — "
                "easily bypassed by direct HTTP requests",
                data={"lockout_threshold": lockout},
            ))
        else:
            self._add(CheckResult("V-11", "Login rate limiting",
                                  "OK", "MEDIUM",
                                  "No client-side lockout mechanism detected"))

    def check_v12_md5_usage(self) -> None:
        """V-12: Check for MD5 usage in authentication."""
        page = self._fetch_login_page()
        if not page:
            self._add(CheckResult("V-12", "MD5 usage",
                                  "SKIP", "LOW",
                                  "Could not fetch login page"))
            return

        if "hex_md5" in page or "MD5(str)" in page:
            self._add(CheckResult(
                "V-12", "MD5 usage", "VULN", "LOW",
                "MD5 functions present in login page (weak hashing)",
            ))
        else:
            self._add(CheckResult("V-12", "MD5 usage",
                                  "OK", "LOW", "No MD5 functions detected"))

    def check_v19_userlevel_escalation(self) -> None:
        """V-19: Check for client-side Userlevel privilege escalation."""
        page = self._fetch_login_page()
        if not page:
            self._add(CheckResult("V-19", "Client-side Userlevel escalation",
                                  "SKIP", "CRITICAL",
                                  "Could not fetch login page"))
            return

        has_userlevel = "var Userlevel" in page
        has_admin_check = "Userlevel == 2" in page
        has_admin_cgi = "MdfPwdAdminNoLg.cgi" in page
        has_normal_cgi = "MdfPwdNormalNoLg.cgi" in page

        if has_userlevel and has_admin_check and has_admin_cgi:
            self._add(CheckResult(
                "V-19", "Client-side Userlevel escalation", "VULN", "CRITICAL",
                "Userlevel variable controls admin path selection client-side; "
                "MdfPwdAdminNoLg.cgi reachable by setting Userlevel=2 in console",
                data={"has_admin_cgi": has_admin_cgi,
                      "has_normal_cgi": has_normal_cgi},
            ))
        elif has_userlevel:
            self._add(CheckResult(
                "V-19", "Client-side Userlevel escalation", "VULN", "HIGH",
                "Userlevel variable present but admin CGI path not found",
            ))
        else:
            self._add(CheckResult("V-19", "Client-side Userlevel escalation",
                                  "OK", "CRITICAL",
                                  "No client-side Userlevel pattern found"))

    def check_v20_dbaa1_admin_bypass(self) -> None:
        """V-20: Check for DBAA1 hardcoded admin account bypass."""
        page = self._fetch_login_page()
        if not page:
            self._add(CheckResult("V-20", "DBAA1 admin bypass",
                                  "SKIP", "CRITICAL",
                                  "Could not fetch login page"))
            return

        has_dbaa1_var = "var DBAA1" in page
        # The empty-password bypass: (DBAA1 != '1') && (Password.value == "")
        has_empty_pwd_bypass = ("DBAA1 != '1'" in page
                                and 'Password.value == ""' in page)
        has_admin_hardcode = 'txt_Username\').value = "admin"' in page

        dbaa1_active = False
        m = re.search(r"var\s+DBAA1\s*=\s*'([^']*)'", page)
        if m:
            dbaa1_active = m.group(1) == "1"

        if dbaa1_active:
            self._add(CheckResult(
                "V-20", "DBAA1 admin bypass", "VULN", "CRITICAL",
                "DBAA1='1' active — admin username hardcoded, "
                "empty password check bypassed",
            ))
        elif has_dbaa1_var and has_empty_pwd_bypass:
            self._add(CheckResult(
                "V-20", "DBAA1 admin bypass", "VULN", "HIGH",
                "DBAA1 bypass code present (inactive: DBAA1='0'); "
                "can be activated via console: DBAA1='1'",
                data={"has_admin_hardcode": has_admin_hardcode},
            ))
        else:
            self._add(CheckResult("V-20", "DBAA1 admin bypass",
                                  "OK", "CRITICAL",
                                  "No DBAA1 bypass pattern found"))

    def check_v21_antel_default_creds(self) -> None:
        """V-21: Check if default credentials are leaked in HTML."""
        page = self._fetch_login_page()
        if not page:
            self._add(CheckResult("V-21", "ANTEL default credential leak",
                                  "SKIP", "CRITICAL",
                                  "Could not fetch login page"))
            return

        m_user = re.search(r"var\s+defaultUsername\s*=\s*'([^']*)'", page)
        m_pass = re.search(r"var\s+defaultPassword\s*=\s*'([^']*)'", page)
        m_mode = re.search(r"var\s+CfgMode\s*=\s*'([^']*)'", page)
        has_autofill = "val(defaultUsername)" in page

        default_user = m_user.group(1) if m_user else ""
        default_pass = m_pass.group(1) if m_pass else ""
        cfg_mode = m_mode.group(1) if m_mode else ""

        if default_user and default_pass:
            self._add(CheckResult(
                "V-21", "ANTEL default credential leak", "VULN", "CRITICAL",
                f"Default credentials in HTML: user='{default_user}', "
                f"password present (CfgMode={cfg_mode})",
                data={"defaultUsername": default_user, "CfgMode": cfg_mode},
            ))
        elif has_autofill:
            self._add(CheckResult(
                "V-21", "ANTEL default credential leak", "VULN", "MEDIUM",
                "Auto-fill code present but credentials currently empty "
                f"(CfgMode={cfg_mode})",
            ))
        else:
            self._add(CheckResult("V-21", "ANTEL default credential leak",
                                  "OK", "CRITICAL",
                                  "No default credential auto-fill detected"))

    def check_v22_language_path_traversal(self) -> None:
        """V-22: Check for language parameter path traversal."""
        page = self._fetch_login_page()
        if not page:
            self._add(CheckResult("V-22", "Language path traversal",
                                  "SKIP", "HIGH",
                                  "Could not fetch login page"))
            return

        # Check for dynamic script loading with Language variable
        has_dynamic_load = ("loadLanguage" in page or
                            "ssmpdes.js" in page or
                            "frameaspdes" in page)
        has_language_concat = ("frameaspdes/" in page and
                               "Language" in page)

        if has_dynamic_load and has_language_concat:
            self._add(CheckResult(
                "V-22", "Language path traversal", "VULN", "HIGH",
                "Language parameter used in script src path construction "
                "without sanitization — path traversal possible",
            ))
        else:
            self._add(CheckResult("V-22", "Language path traversal",
                                  "OK", "HIGH",
                                  "No dynamic language script loading detected"))

    def check_v23_pbkdf2_downgrade(self) -> None:
        """V-23: Check for server-controlled PBKDF2 iterations."""
        page = self._fetch_login_page()
        if not page:
            self._add(CheckResult("V-23", "PBKDF2 iterations downgrade",
                                  "SKIP", "HIGH",
                                  "Could not fetch login page"))
            return

        has_getrandinfo = "GetRandInfo.asp" in page
        has_pbkdf2 = "CryptoJS.PBKDF2" in page
        has_server_iterations = "parseInt(infos[2])" in page

        if has_pbkdf2 and has_server_iterations:
            self._add(CheckResult(
                "V-23", "PBKDF2 iterations downgrade", "VULN", "HIGH",
                "PBKDF2 iteration count from server response (infos[2]) — "
                "MITM can set iterations=1 for trivial brute-force",
                data={"has_getrandinfo": has_getrandinfo},
            ))
        elif has_pbkdf2:
            self._add(CheckResult(
                "V-23", "PBKDF2 iterations downgrade", "VULN", "MEDIUM",
                "PBKDF2 present but server-controlled iterations not confirmed",
            ))
        else:
            self._add(CheckResult("V-23", "PBKDF2 iterations downgrade",
                                  "OK", "HIGH",
                                  "No PBKDF2 with server-controlled iterations"))

    def check_v24_dom_xss(self) -> None:
        """V-24: Check for DOM-based XSS via innerHTML without encoding."""
        page = self._fetch_login_page()
        if not page:
            self._add(CheckResult("V-24", "DOM-based XSS (innerHTML)",
                                  "SKIP", "HIGH",
                                  "Could not fetch login page"))
            return

        has_set_div = "SetDivValue" in page
        has_innerhtml = ".innerHTML" in page
        # Count calls to SetDivValue which uses raw innerHTML
        count = page.count("SetDivValue")

        if has_set_div and count > 0:
            self._add(CheckResult(
                "V-24", "DOM-based XSS (innerHTML)", "VULN", "HIGH",
                f"SetDivValue() (raw innerHTML) called {count} time(s) in login page; "
                "also setObjNoEncodeInnerHtmlValue in util.js",
                data={"setdivvalue_count": count},
            ))
        elif has_innerhtml:
            self._add(CheckResult(
                "V-24", "DOM-based XSS (innerHTML)", "VULN", "MEDIUM",
                "innerHTML usage found but SetDivValue not present",
            ))
        else:
            self._add(CheckResult("V-24", "DOM-based XSS (innerHTML)",
                                  "OK", "HIGH",
                                  "No raw innerHTML patterns detected"))

    def check_v25_sensitive_tr069_paths(self) -> None:
        """V-25: Probe TR-069 paths for certs, keys, and credentials."""
        if not self._is_logged_in:
            if not self._login():
                self._add(CheckResult(
                    "V-25", "Sensitive TR-069 data extraction", "SKIP", "CRITICAL",
                    "Login required but credentials not provided or login failed",
                ))
                return

        accessible = []
        # Minimum response length to distinguish real data from empty/error stubs
        min_data_len = 10
        for path, description in TR069_SENSITIVE_PATHS:
            resp = self._post(f"/getajax.cgi?{path}")
            if resp and resp.ok and len(resp.text.strip()) > min_data_len:
                text = resp.text.strip()
                if "error" not in text.lower() and text != "{ }":
                    accessible.append({"path": path, "description": description,
                                       "response_length": len(text)})
                    log.debug("  SENSITIVE %s → %d bytes", path, len(text))

        if accessible:
            self._add(CheckResult(
                "V-25", "Sensitive TR-069 data extraction", "VULN", "CRITICAL",
                f"{len(accessible)}/{len(TR069_SENSITIVE_PATHS)} sensitive paths "
                f"returned data (certs, keys, credentials, GPON params)",
                data={"accessible": accessible},
            ))
        else:
            self._add(CheckResult(
                "V-25", "Sensitive TR-069 data extraction", "OK", "CRITICAL",
                "No sensitive TR-069 paths returned data",
            ))

    def check_v26_write_endpoints(self) -> None:
        """V-26: Check for authenticated arbitrary write endpoints."""
        page = self._fetch_login_page()
        if not page:
            self._add(CheckResult("V-26", "Arbitrary write endpoints",
                                  "SKIP", "CRITICAL",
                                  "Could not fetch login page"))
            return

        has_hwgetaction = "HWGetAction" in page
        # Check util.js patterns
        write_indicators = []
        for pattern in ("HWGetAction", "ajaxSumitData", "setajax.cgi",
                        "cfgaction.cgi", "configservice.cgi"):
            if pattern in (page or ""):
                write_indicators.append(pattern)

        # Probe write endpoints (GET only — read-only probe)
        write_endpoints = ["/setajax.cgi", "/cfgaction.cgi",
                           "/configservice.cgi", "/set.cgi"]
        accessible_write = []
        for ep in write_endpoints:
            resp = self._get(ep)
            if resp and resp.status_code not in (404, 405):
                accessible_write.append(f"{ep} (HTTP {resp.status_code})")

        if accessible_write:
            self._add(CheckResult(
                "V-26", "Arbitrary write endpoints", "VULN", "CRITICAL",
                f"Write endpoints accessible: {', '.join(accessible_write)}",
                data={"endpoints": accessible_write,
                      "code_patterns": write_indicators},
            ))
        elif write_indicators:
            self._add(CheckResult(
                "V-26", "Arbitrary write endpoints", "VULN", "HIGH",
                f"Write functions in code: {', '.join(write_indicators)} "
                "(endpoints not probed without auth)",
            ))
        else:
            self._add(CheckResult("V-26", "Arbitrary write endpoints",
                                  "OK", "CRITICAL",
                                  "No write endpoint patterns found"))

    def check_v27_response_chain_rce(self) -> None:
        """V-27: Check for hexDecode+dealDataWithFun response chain."""
        page = self._fetch_login_page()
        if not page:
            self._add(CheckResult("V-27", "Response chain RCE",
                                  "SKIP", "CRITICAL",
                                  "Could not fetch login page"))
            return

        has_hexdecode = "hexDecode" in page
        has_dealdatawithfun = "dealDataWithFun" in page
        has_function_constructor = "Function(" in page

        if has_dealdatawithfun and has_function_constructor:
            severity = "CRITICAL"
            details = ("dealDataWithFun() + Function() constructor present — "
                       "all AJAX responses are executed as code")
            if has_hexdecode:
                details += "; hexDecode allows obfuscated payloads"
            self._add(CheckResult(
                "V-27", "Response chain RCE", "VULN", severity, details,
                data={"hexDecode": has_hexdecode,
                      "dealDataWithFun": has_dealdatawithfun},
            ))
        else:
            self._add(CheckResult("V-27", "Response chain RCE",
                                  "OK", "CRITICAL",
                                  "No dangerous response processing chain found"))

    def check_v28_requestfile_injection(self) -> None:
        """V-28: Check for RequestFile parameter injection."""
        page = self._fetch_login_page()
        if not page:
            self._add(CheckResult("V-28", "RequestFile parameter injection",
                                  "SKIP", "HIGH",
                                  "Could not fetch login page"))
            return

        requestfile_refs = page.count("RequestFile=")
        has_submittype = "SubmitType" in page
        has_checkcodeerrfile = "CheckCodeErrFile" in page

        injection_points = []
        if requestfile_refs > 0:
            injection_points.append(f"RequestFile= ({requestfile_refs} refs)")
        if has_submittype:
            injection_points.append("SubmitType")
        if has_checkcodeerrfile:
            injection_points.append("CheckCodeErrFile")

        if injection_points:
            self._add(CheckResult(
                "V-28", "RequestFile parameter injection", "VULN", "HIGH",
                f"Unsanitized redirect parameters: {', '.join(injection_points)} — "
                "open redirect / path traversal possible",
                data={"injection_points": injection_points,
                      "requestfile_count": requestfile_refs},
            ))
        else:
            self._add(CheckResult("V-28", "RequestFile parameter injection",
                                  "OK", "HIGH",
                                  "No RequestFile injection patterns found"))

    def check_endpoint_accessibility(self) -> None:
        """Bonus: Probe all known endpoints for accessibility."""
        for endpoint in PRE_LOGIN_ENDPOINTS:
            resp = self._get(endpoint)
            status = resp.status_code if resp else "unreachable"
            log.debug("  %s → %s", endpoint, status)

    # ---------------------------------------------------------------
    # Run all checks
    # ---------------------------------------------------------------
    def run_all(self) -> list[CheckResult]:
        """Execute all security checks and return results."""
        log.info("=" * 60)
        log.info("Security Audit — Huawei HG8145V5")
        log.info("Target: %s", self.base)
        log.info("=" * 60)

        # Verify target is reachable
        resp = self._get("/")
        if not resp:
            log.error("Cannot reach %s — is the router accessible?", self.base)
            self._add(CheckResult(
                "CONN", "Connectivity check", "ERROR", "CRITICAL",
                f"Cannot reach {self.base}",
            ))
            return self.results

        log.info("Router is reachable (HTTP %s)", resp.status_code)
        log.info("-" * 60)

        # Run all checks
        self.check_v01_base64_password()
        self.check_v02_prelogin_token()
        self.check_v03_password_oracle()
        self.check_v04_csrf_token()
        self.check_v05_eval_in_code()
        self.check_v06_cookie_attributes()
        self.check_v07_framemode_switch()
        self.check_v09_noauth_password_change()
        self.check_v10_leaked_variables()
        self.check_v11_login_rate_limit()
        self.check_v12_md5_usage()
        self.check_v19_userlevel_escalation()
        self.check_v20_dbaa1_admin_bypass()
        self.check_v21_antel_default_creds()
        self.check_v22_language_path_traversal()
        self.check_v23_pbkdf2_downgrade()
        self.check_v24_dom_xss()
        self.check_v26_write_endpoints()
        self.check_v27_response_chain_rce()
        self.check_v28_requestfile_injection()

        # Auth-required checks (only if credentials provided)
        if self.username and self.password:
            self.check_v08_tr069_paths()
            self.check_v25_sensitive_tr069_paths()
        else:
            self._add(CheckResult(
                "V-08", "TR-069 path traversal", "SKIP", "HIGH",
                "Provide --user and --password to test authenticated endpoints",
            ))
            self._add(CheckResult(
                "V-25", "Sensitive TR-069 data extraction", "SKIP", "CRITICAL",
                "Provide --user and --password to test authenticated endpoints",
            ))

        # Summary
        log.info("=" * 60)
        vulns = sum(1 for r in self.results if r.status == "VULN")
        oks = sum(1 for r in self.results if r.status == "OK")
        skips = sum(1 for r in self.results if r.status == "SKIP")
        log.info(
            "Summary: %d VULNERABLE, %d OK, %d SKIPPED out of %d checks",
            vulns, oks, skips, len(self.results),
        )
        log.info("=" * 60)

        return self.results

    def to_json(self) -> str:
        """Serialize results to JSON."""
        return json.dumps(
            [
                {
                    "check_id": r.check_id,
                    "title": r.title,
                    "status": r.status,
                    "severity": r.severity,
                    "details": r.details,
                    "data": r.data,
                }
                for r in self.results
            ],
            indent=2,
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Security audit tool for Huawei HG8145V5 router"
    )
    parser.add_argument("--host", default="192.168.100.1",
                        help="Router IP address (default: 192.168.100.1)")
    parser.add_argument("--user", default=None,
                        help="Admin username (for authenticated checks)")
    parser.add_argument("--password", default=None,
                        help="Admin password (for authenticated checks)")
    parser.add_argument("--no-verify-ssl", action="store_true",
                        help="Disable TLS certificate verification")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--output", type=str, default=None,
                        help="Save JSON results to file")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.no_verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    audit = SecurityAudit(
        host=args.host,
        username=args.user,
        password=args.password,
        verify_ssl=not args.no_verify_ssl,
    )
    results = audit.run_all()

    if args.json:
        print(audit.to_json())

    if args.output:
        Path(args.output).write_text(audit.to_json())
        log.info("Results saved to %s", args.output)


if __name__ == "__main__":
    main()
