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

        # Auth-required checks (only if credentials provided)
        if self.username and self.password:
            self.check_v08_tr069_paths()
        else:
            self._add(CheckResult(
                "V-08", "TR-069 path traversal", "SKIP", "HIGH",
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
