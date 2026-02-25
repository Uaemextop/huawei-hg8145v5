"""Tests for the security audit tool.

These tests mock HTTP responses to verify vulnerability detection logic
without needing an actual router.
"""

import importlib
import json
import os
import unittest
from unittest.mock import MagicMock, patch

from tools.security_audit import SecurityAudit, CheckResult


def _mock_response(status_code=200, text="", ok=True, headers=None):
    """Create a mock requests.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.ok = ok
    resp.headers = headers or {"Content-Type": "text/html"}
    resp.content = text.encode("utf-8") if isinstance(text, str) else text
    return resp


# Minimal index.asp content with known vulnerability patterns
MOCK_INDEX_ASP = """
<html><head>
<script language="JavaScript" type="text/javascript">
  var useChallengeCode = '1';
  var randcode = '20260221';
  function MD5(str) { return hex_md5(str); }
  var FailStat = '0';
  var LoginTimes = '0';
  var errloginlockNum = '3';
  var LockLeftTime = '0';
  var CfgMode = 'MEGACABLE2';
  var ProductName = 'HG8145V5-12';
  var ProductType = '1';
  var DBAA1 = '0';
  var Userlevel = 0;
  var defaultUsername = '';
  var defaultPassword = '';
  var APPVersion = '1.1.1.1';
  var Ssid1 = 'MyWifi';
  var Ssid2 = '';

  function dealDataWithFun(str) {
    if (typeof str === 'string' && str.indexOf('function') === 0) {
      return Function('"use strict";return (' + str + ')')()();
    }
    return str;
  }

  if (Userlevel == 2) { return true; }
  Form.setAction('MdfPwdAdminNoLg.cgi?&z=InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.2');
  Form.setAction('MdfPwdNormalNoLg.cgi?&z=InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.1');

  if ((DBAA1 != '1') && (Password.value == "")) { return false; }
  document.getElementById('txt_Username').value = "admin";

  if ((CfgMode.toUpperCase() == 'ANTEL2') || (CfgMode.toUpperCase() == 'ANTEL')) {
    $("#txt_Username").val(defaultUsername);
    $("#txt_Password").val(defaultPassword);
  }

  var url = "/frameaspdes/" + Language + "/ssmpdes.js";
  loadLanguage(id, url, callback);

  var pwdPbkf2 = CryptoJS.PBKDF2(Password.value, infos[1], {
    keySize: 8,
    hasher: CryptoJS.algo.SHA256,
    iterations: parseInt(infos[2])
  });

  SetDivValue("DivErrPromt", GetLoginDes("frame014"));
  SetDivValue("DivErrIcon", html);

  result = hexDecode(data);
  result = dealDataWithFun(data);
  return Function('"use strict";return (' + str + ')')()();

  Form.setAction('login.cgi?&CheckCodeErrFile=login.asp');
  Form.setAction('logout.cgi?RequestFile=html/logout.html');
  url += '&SubmitType=' + submitType;

  url : 'FrameModeSwitch.cgi?&RequestFile=/login.asp',
  data  : 'X_HW_FrameMode=2',

  Form.addParameter('x.X_HW_Token', getValue('onttoken'));
  Form.addParameter('PassWord', base64encode(Password.value));
  Form.submit();

  var cookie2 = "Cookie=body:" + "Language:" + Language + ":" + "id=-1;path=/";
  document.cookie = cookie2;
</script>
<input id="txt_Username" />
<input id="txt_Password" />
<button class="loginbutton" />
</head></html>
"""

MOCK_TOKEN = "abc123def456abc123def456abc123def456abc123def456"
MOCK_CSRF_TOKEN = "332eb228ae4423a4d8ee0e17b0d585628a16465236ff1fd6"


class TestSecurityAuditChecks(unittest.TestCase):
    """Test individual vulnerability checks with mocked responses."""

    def _make_audit(self):
        """Create an audit instance with mocked session."""
        audit = SecurityAudit("192.168.100.1")
        audit.session = MagicMock()
        return audit

    def test_v01_base64_password_detected(self):
        audit = self._make_audit()
        audit._login_page_text = MOCK_INDEX_ASP
        audit.check_v01_base64_password()
        self.assertEqual(len(audit.results), 1)
        self.assertEqual(audit.results[0].status, "VULN")
        self.assertEqual(audit.results[0].check_id, "V-01")

    def test_v01_base64_password_not_detected(self):
        audit = self._make_audit()
        audit._login_page_text = "<html><body>no password encoding</body></html>"
        audit.check_v01_base64_password()
        self.assertEqual(audit.results[0].status, "OK")

    def test_v02_prelogin_token_accessible(self):
        audit = self._make_audit()
        audit.session.post.return_value = _mock_response(text=MOCK_TOKEN)
        audit.check_v02_prelogin_token()
        self.assertEqual(audit.results[0].status, "VULN")
        self.assertEqual(audit.results[0].check_id, "V-02")

    def test_v02_prelogin_token_not_accessible(self):
        audit = self._make_audit()
        audit.session.post.return_value = _mock_response(status_code=404, ok=False, text="")
        audit.check_v02_prelogin_token()
        self.assertEqual(audit.results[0].status, "OK")

    def test_v03_password_oracle_exists(self):
        audit = self._make_audit()
        audit.session.post.return_value = _mock_response(text="0")
        audit.check_v03_password_oracle()
        self.assertEqual(audit.results[0].status, "VULN")
        self.assertEqual(audit.results[0].check_id, "V-03")

    def test_v03_password_oracle_404(self):
        audit = self._make_audit()
        audit.session.post.return_value = _mock_response(status_code=404, ok=False)
        audit.check_v03_password_oracle()
        self.assertEqual(audit.results[0].status, "OK")

    def test_v04_csrf_token_analysis(self):
        audit = self._make_audit()
        audit.session.post.return_value = _mock_response(text=MOCK_CSRF_TOKEN)
        audit.check_v04_csrf_token()
        self.assertEqual(audit.results[0].status, "VULN")
        self.assertIn("48", audit.results[0].details)  # token length

    def test_v05_eval_detected(self):
        audit = self._make_audit()
        audit._login_page_text = MOCK_INDEX_ASP
        audit.check_v05_eval_in_code()
        self.assertEqual(audit.results[0].status, "VULN")
        self.assertEqual(audit.results[0].severity, "CRITICAL")

    def test_v05_eval_not_detected(self):
        audit = self._make_audit()
        audit._login_page_text = "<html><body>safe code</body></html>"
        audit.check_v05_eval_in_code()
        self.assertEqual(audit.results[0].status, "OK")

    def test_v06_cookie_no_security_attrs(self):
        audit = self._make_audit()
        audit._login_page_text = MOCK_INDEX_ASP
        audit.check_v06_cookie_attributes()
        self.assertEqual(audit.results[0].status, "VULN")
        issues = audit.results[0].data.get("issues", [])
        self.assertIn("No HttpOnly flag", issues)

    def test_v07_framemode_accessible(self):
        audit = self._make_audit()
        audit.session.get.return_value = _mock_response(status_code=200, text="OK")
        audit.check_v07_framemode_switch()
        self.assertEqual(audit.results[0].status, "VULN")

    def test_v07_framemode_not_found(self):
        audit = self._make_audit()
        audit.session.get.return_value = _mock_response(status_code=404, ok=False)
        audit.check_v07_framemode_switch()
        self.assertEqual(audit.results[0].status, "OK")

    def test_v09_noauth_pwd_change_exists(self):
        audit = self._make_audit()
        audit.session.get.return_value = _mock_response(status_code=200, text="OK")
        audit.check_v09_noauth_password_change()
        # Two endpoints checked
        self.assertEqual(len(audit.results), 2)
        self.assertTrue(all(r.status == "VULN" for r in audit.results))

    def test_v09_noauth_pwd_change_not_found(self):
        audit = self._make_audit()
        audit.session.get.return_value = _mock_response(status_code=404, ok=False)
        audit.check_v09_noauth_password_change()
        self.assertTrue(all(r.status == "OK" for r in audit.results))

    def test_v10_leaked_variables(self):
        audit = self._make_audit()
        audit._login_page_text = MOCK_INDEX_ASP
        audit.check_v10_leaked_variables()
        self.assertEqual(audit.results[0].status, "VULN")
        leaked = audit.results[0].data["leaked"]
        self.assertEqual(leaked["CfgMode"], "MEGACABLE2")
        self.assertEqual(leaked["ProductName"], "HG8145V5-12")
        self.assertEqual(leaked["Ssid1"], "MyWifi")
        self.assertEqual(leaked["errloginlockNum"], "3")

    def test_v10_default_credentials_leaked(self):
        """V-10: Detect leaked default credentials (ANTEL-style)."""
        page_with_creds = MOCK_INDEX_ASP.replace(
            "var defaultUsername = '';",
            "var defaultUsername = 'admin';"
        ).replace(
            "var defaultPassword = '';",
            "var defaultPassword = 's3cret';"
        )
        audit = self._make_audit()
        audit._login_page_text = page_with_creds
        audit.check_v10_leaked_variables()
        self.assertEqual(audit.results[0].severity, "HIGH")  # Elevated severity
        self.assertIn("defaultUsername", audit.results[0].details)

    def test_v11_client_side_lockout(self):
        audit = self._make_audit()
        audit._login_page_text = MOCK_INDEX_ASP
        audit.check_v11_login_rate_limit()
        self.assertEqual(audit.results[0].status, "VULN")
        self.assertIn("3", audit.results[0].details)

    def test_v12_md5_detected(self):
        audit = self._make_audit()
        audit._login_page_text = MOCK_INDEX_ASP
        audit.check_v12_md5_usage()
        self.assertEqual(audit.results[0].status, "VULN")

    def test_v12_md5_not_detected(self):
        audit = self._make_audit()
        audit._login_page_text = "<html>no md5 here</html>"
        audit.check_v12_md5_usage()
        self.assertEqual(audit.results[0].status, "OK")

    # --- V-19: Userlevel escalation ---
    def test_v19_userlevel_escalation_detected(self):
        audit = self._make_audit()
        audit._login_page_text = MOCK_INDEX_ASP
        audit.check_v19_userlevel_escalation()
        self.assertEqual(audit.results[0].status, "VULN")
        self.assertEqual(audit.results[0].severity, "CRITICAL")
        self.assertIn("MdfPwdAdminNoLg.cgi", audit.results[0].details)

    def test_v19_userlevel_not_detected(self):
        audit = self._make_audit()
        audit._login_page_text = "<html>no userlevel</html>"
        audit.check_v19_userlevel_escalation()
        self.assertEqual(audit.results[0].status, "OK")

    # --- V-20: DBAA1 admin bypass ---
    def test_v20_dbaa1_active(self):
        page = MOCK_INDEX_ASP.replace("var DBAA1 = '0';", "var DBAA1 = '1';")
        audit = self._make_audit()
        audit._login_page_text = page
        audit.check_v20_dbaa1_admin_bypass()
        self.assertEqual(audit.results[0].status, "VULN")
        self.assertEqual(audit.results[0].severity, "CRITICAL")

    def test_v20_dbaa1_inactive_but_code_present(self):
        audit = self._make_audit()
        audit._login_page_text = MOCK_INDEX_ASP  # DBAA1 = '0'
        audit.check_v20_dbaa1_admin_bypass()
        self.assertEqual(audit.results[0].status, "VULN")
        self.assertEqual(audit.results[0].severity, "HIGH")

    def test_v20_dbaa1_not_present(self):
        audit = self._make_audit()
        audit._login_page_text = "<html>no dbaa1</html>"
        audit.check_v20_dbaa1_admin_bypass()
        self.assertEqual(audit.results[0].status, "OK")

    # --- V-21: ANTEL default credential leak ---
    def test_v21_antel_creds_leaked(self):
        page = MOCK_INDEX_ASP.replace(
            "var defaultUsername = '';", "var defaultUsername = 'admin';"
        ).replace(
            "var defaultPassword = '';", "var defaultPassword = 's3cret';"
        )
        audit = self._make_audit()
        audit._login_page_text = page
        audit.check_v21_antel_default_creds()
        self.assertEqual(audit.results[0].status, "VULN")
        self.assertEqual(audit.results[0].severity, "CRITICAL")

    def test_v21_antel_autofill_code_present(self):
        audit = self._make_audit()
        audit._login_page_text = MOCK_INDEX_ASP  # empty creds but autofill code
        audit.check_v21_antel_default_creds()
        self.assertEqual(audit.results[0].status, "VULN")
        self.assertEqual(audit.results[0].severity, "MEDIUM")

    def test_v21_antel_not_detected(self):
        audit = self._make_audit()
        audit._login_page_text = "<html>no antel</html>"
        audit.check_v21_antel_default_creds()
        self.assertEqual(audit.results[0].status, "OK")

    # --- V-22: Language path traversal ---
    def test_v22_language_traversal_detected(self):
        audit = self._make_audit()
        audit._login_page_text = MOCK_INDEX_ASP
        audit.check_v22_language_path_traversal()
        self.assertEqual(audit.results[0].status, "VULN")

    def test_v22_language_traversal_not_detected(self):
        audit = self._make_audit()
        audit._login_page_text = "<html>no language loading</html>"
        audit.check_v22_language_path_traversal()
        self.assertEqual(audit.results[0].status, "OK")

    # --- V-23: PBKDF2 iterations downgrade ---
    def test_v23_pbkdf2_downgrade_detected(self):
        audit = self._make_audit()
        audit._login_page_text = MOCK_INDEX_ASP
        audit.check_v23_pbkdf2_downgrade()
        self.assertEqual(audit.results[0].status, "VULN")
        self.assertIn("iterations=1", audit.results[0].details)

    def test_v23_pbkdf2_not_detected(self):
        audit = self._make_audit()
        audit._login_page_text = "<html>no pbkdf2</html>"
        audit.check_v23_pbkdf2_downgrade()
        self.assertEqual(audit.results[0].status, "OK")

    # --- V-24: DOM XSS ---
    def test_v24_dom_xss_detected(self):
        audit = self._make_audit()
        audit._login_page_text = MOCK_INDEX_ASP
        audit.check_v24_dom_xss()
        self.assertEqual(audit.results[0].status, "VULN")
        self.assertIn("SetDivValue", audit.results[0].details)
        self.assertEqual(audit.results[0].data["setdivvalue_count"], 2)

    def test_v24_dom_xss_not_detected(self):
        audit = self._make_audit()
        audit._login_page_text = "<html>safe page</html>"
        audit.check_v24_dom_xss()
        self.assertEqual(audit.results[0].status, "OK")

    # --- V-25: Sensitive TR-069 paths ---
    def test_v25_sensitive_paths_accessible(self):
        audit = self._make_audit()
        audit._is_logged_in = True
        audit.session.post.return_value = _mock_response(
            text='{"X_HW_Certificate":"-----BEGIN CERTIFICATE-----\\nMII..."}'
        )
        audit.check_v25_sensitive_tr069_paths()
        self.assertEqual(audit.results[0].status, "VULN")
        self.assertEqual(audit.results[0].severity, "CRITICAL")

    def test_v25_sensitive_paths_not_accessible(self):
        audit = self._make_audit()
        audit._is_logged_in = True
        audit.session.post.return_value = _mock_response(text="{ }")
        audit.check_v25_sensitive_tr069_paths()
        self.assertEqual(audit.results[0].status, "OK")

    def test_v25_sensitive_paths_skip_no_login(self):
        audit = self._make_audit()
        audit._is_logged_in = False
        audit.check_v25_sensitive_tr069_paths()
        self.assertEqual(audit.results[0].status, "SKIP")

    # --- V-26: Write endpoints ---
    def test_v26_write_endpoints_accessible(self):
        audit = self._make_audit()
        audit._login_page_text = MOCK_INDEX_ASP
        audit.session.get.return_value = _mock_response(status_code=200, text="OK")
        audit.check_v26_write_endpoints()
        self.assertEqual(audit.results[0].status, "VULN")

    def test_v26_write_endpoints_404(self):
        audit = self._make_audit()
        audit._login_page_text = "<html>no write patterns</html>"
        audit.session.get.return_value = _mock_response(status_code=404, ok=False)
        audit.check_v26_write_endpoints()
        self.assertEqual(audit.results[0].status, "OK")

    # --- V-27: Response chain RCE ---
    def test_v27_response_chain_detected(self):
        audit = self._make_audit()
        audit._login_page_text = MOCK_INDEX_ASP
        audit.check_v27_response_chain_rce()
        self.assertEqual(audit.results[0].status, "VULN")
        self.assertEqual(audit.results[0].severity, "CRITICAL")
        self.assertIn("dealDataWithFun", audit.results[0].details)
        self.assertTrue(audit.results[0].data["hexDecode"])

    def test_v27_response_chain_not_detected(self):
        audit = self._make_audit()
        audit._login_page_text = "<html>safe page</html>"
        audit.check_v27_response_chain_rce()
        self.assertEqual(audit.results[0].status, "OK")

    # --- V-28: RequestFile injection ---
    def test_v28_requestfile_injection_detected(self):
        audit = self._make_audit()
        audit._login_page_text = MOCK_INDEX_ASP
        audit.check_v28_requestfile_injection()
        self.assertEqual(audit.results[0].status, "VULN")
        self.assertIn("RequestFile", audit.results[0].details)
        self.assertIn("CheckCodeErrFile", audit.results[0].details)
        self.assertIn("SubmitType", audit.results[0].details)

    def test_v28_requestfile_injection_not_detected(self):
        audit = self._make_audit()
        audit._login_page_text = "<html>no requestfile</html>"
        audit.check_v28_requestfile_injection()
        self.assertEqual(audit.results[0].status, "OK")

    # --- V-29: CfgMode switch via FrameModeSwitch ---
    def test_v29_cfgmode_switch_accessible(self):
        audit = self._make_audit()
        audit._login_page_text = MOCK_INDEX_ASP
        audit.session.get.return_value = _mock_response(status_code=200, text="OK")
        audit.check_v29_cfgmode_switch()
        self.assertEqual(audit.results[0].status, "VULN")
        self.assertEqual(audit.results[0].severity, "CRITICAL")
        self.assertIn("MEGACABLE2", audit.results[0].details)
        self.assertIn("PLDT", audit.results[0].details)

    def test_v29_cfgmode_switch_code_only(self):
        audit = self._make_audit()
        audit._login_page_text = MOCK_INDEX_ASP
        audit.session.get.return_value = _mock_response(status_code=404, ok=False)
        audit.check_v29_cfgmode_switch()
        self.assertEqual(audit.results[0].status, "VULN")
        self.assertEqual(audit.results[0].severity, "HIGH")

    def test_v29_cfgmode_switch_not_detected(self):
        audit = self._make_audit()
        audit._login_page_text = "<html>no framemode</html>"
        audit.session.get.return_value = _mock_response(status_code=404, ok=False)
        audit.check_v29_cfgmode_switch()
        self.assertEqual(audit.results[0].status, "OK")

    # --- V-30: randcode leak ---
    def test_v30_randcode_leak_active(self):
        audit = self._make_audit()
        audit._login_page_text = MOCK_INDEX_ASP
        audit.check_v30_randcode_leak()
        self.assertEqual(audit.results[0].status, "VULN")
        self.assertEqual(audit.results[0].severity, "HIGH")
        self.assertIn("20260221", audit.results[0].details)
        self.assertEqual(audit.results[0].data["randcode"], "20260221")

    def test_v30_randcode_leak_disabled(self):
        page = MOCK_INDEX_ASP.replace(
            "var useChallengeCode = '1';",
            "var useChallengeCode = '0';"
        )
        audit = self._make_audit()
        audit._login_page_text = page
        audit.check_v30_randcode_leak()
        self.assertEqual(audit.results[0].status, "VULN")
        self.assertEqual(audit.results[0].severity, "MEDIUM")

    def test_v30_randcode_not_present(self):
        audit = self._make_audit()
        audit._login_page_text = "<html>no randcode</html>"
        audit.check_v30_randcode_leak()
        self.assertEqual(audit.results[0].status, "OK")

    # --- V-31: onttoken DOM exposure ---
    def test_v31_onttoken_exposed(self):
        audit = self._make_audit()
        audit._login_page_text = MOCK_INDEX_ASP
        audit.check_v31_onttoken_dom_exposure()
        self.assertEqual(audit.results[0].status, "VULN")
        self.assertIn("onttoken", audit.results[0].details)

    def test_v31_onttoken_not_found(self):
        audit = self._make_audit()
        audit._login_page_text = "<html>no token element</html>"
        audit.check_v31_onttoken_dom_exposure()
        self.assertEqual(audit.results[0].status, "OK")

    # --- V-32: Form chain without sanitization ---
    def test_v32_no_sanitization_detected(self):
        audit = self._make_audit()
        audit._login_page_text = MOCK_INDEX_ASP
        audit.check_v32_no_input_sanitization()
        self.assertEqual(audit.results[0].status, "VULN")
        issues = audit.results[0].data["issues"]
        self.assertIn("getValue() returns raw element.value", issues)
        self.assertIn("addParameter() stores raw values", issues)

    def test_v32_no_sanitization_not_detected(self):
        audit = self._make_audit()
        audit._login_page_text = "<html>safe forms</html>"
        audit.check_v32_no_input_sanitization()
        self.assertEqual(audit.results[0].status, "OK")


class TestSecurityAuditResults(unittest.TestCase):
    """Test result serialization."""

    def test_to_json(self):
        audit = SecurityAudit("192.168.100.1")
        audit.results = [
            CheckResult("V-01", "Test", "VULN", "HIGH", "test detail"),
            CheckResult("V-02", "Test2", "OK", "LOW"),
        ]
        result = json.loads(audit.to_json())
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["check_id"], "V-01")
        self.assertEqual(result[0]["status"], "VULN")
        self.assertEqual(result[1]["status"], "OK")

    def test_check_result_dataclass(self):
        r = CheckResult("V-01", "title", "VULN", "HIGH", "details",
                        data={"key": "value"})
        self.assertEqual(r.check_id, "V-01")
        self.assertEqual(r.data["key"], "value")


class TestSecurityAuditHelpers(unittest.TestCase):
    """Test helper methods."""

    def test_fetch_login_page_caches(self):
        audit = SecurityAudit("192.168.100.1")
        audit.session = MagicMock()
        audit.session.get.return_value = _mock_response(text=MOCK_INDEX_ASP)
        # First call fetches
        page1 = audit._fetch_login_page()
        self.assertIsNotNone(page1)
        # Second call uses cache
        page2 = audit._fetch_login_page()
        self.assertEqual(page1, page2)
        # Only one HTTP call made
        audit.session.get.assert_called_once()

    def test_fetch_prelogin_token_caches(self):
        audit = SecurityAudit("192.168.100.1")
        audit.session = MagicMock()
        audit.session.post.return_value = _mock_response(text=MOCK_TOKEN)
        t1 = audit._fetch_pre_login_token()
        t2 = audit._fetch_pre_login_token()
        self.assertEqual(t1, t2)
        audit.session.post.assert_called_once()


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Tests for tools/web_challenge_password.py
# ---------------------------------------------------------------------------

def _load_web_challenge_mod():
    spec = importlib.util.spec_from_file_location(
        "web_challenge_password",
        os.path.join(os.path.dirname(__file__), "..", "tools", "web_challenge_password.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestWebChallengePassword(unittest.TestCase):
    """Tests for the standalone web challenge password script."""

    def _mod(self):
        return _load_web_challenge_mod()

    def test_sha256_challenge_19810101(self):
        mod = self._mod()
        self.assertEqual(mod.sha256_challenge("19810101"), "364ce967beff355b")

    def test_sha256_challenge_20260221(self):
        mod = self._mod()
        self.assertEqual(mod.sha256_challenge("20260221"), "96eb2f1c1ff60cc5")

    def test_sha256_full_64_chars(self):
        mod = self._mod()
        result = mod.sha256_full("19810101")
        self.assertEqual(len(result), 64)
        self.assertTrue(result.startswith("364ce967beff355b"))

    def test_md5_challenge(self):
        mod = self._mod()
        result = mod.md5_challenge("19810101")
        self.assertEqual(result, "794d89deb8f6ff87c4a019ee65b15576")

    def test_validate_date_valid(self):
        mod = self._mod()
        self.assertTrue(mod.validate_date("19810101"))
        self.assertTrue(mod.validate_date("20260221"))
        self.assertTrue(mod.validate_date("20000101"))

    def test_validate_date_invalid(self):
        mod = self._mod()
        self.assertFalse(mod.validate_date("invalid"))
        self.assertFalse(mod.validate_date("2026022"))  # 7 chars
        self.assertFalse(mod.validate_date("202602211"))  # 9 chars
        self.assertFalse(mod.validate_date("20261301"))  # month 13
        self.assertFalse(mod.validate_date("abcdefgh"))

    def test_generate_all_codes(self):
        mod = self._mod()
        codes = mod.generate_all_codes("19810101")
        self.assertGreaterEqual(len(codes), 4)
        self.assertEqual(codes[0]["code"], "364ce967beff355b")

    def test_firmware_constants(self):
        mod = self._mod()
        self.assertEqual(mod.AES_KEY, "Df7!ui%s9(lmV1L8")
        self.assertEqual(mod.DEFAULT_SN, "4857544347020CB1")
        self.assertEqual(mod.MEGACABLE_ADMIN_USER, "Mega_gpon")
        self.assertEqual(mod.MEGACABLE_ADMIN_PASSWORD, "admintelecom")

    def test_cli_mode_output(self):
        """Verify cli_mode prints results without error."""
        import io
        from contextlib import redirect_stdout
        mod = self._mod()
        buf = io.StringIO()
        with redirect_stdout(buf):
            mod.cli_mode("19810101")
        output = buf.getvalue()
        self.assertIn("364ce967beff355b", output)
        self.assertIn("19810101", output)


# ---------------------------------------------------------------------------
# Tests for tools/cli_challenge_password.py
# ---------------------------------------------------------------------------

def _load_cli_challenge_mod():
    spec = importlib.util.spec_from_file_location(
        "cli_challenge_password",
        os.path.join(os.path.dirname(__file__), "..", "tools", "cli_challenge_password.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestCliChallengePassword(unittest.TestCase):
    """Tests for the standalone CLI/Telnet challenge password script."""

    def _mod(self):
        return _load_cli_challenge_mod()

    def test_sha256_password_16(self):
        mod = self._mod()
        self.assertEqual(mod.sha256_password("19810101", 16), "364ce967beff355b")

    def test_sha256_password_default_length(self):
        mod = self._mod()
        result = mod.sha256_password("19810101")
        self.assertEqual(len(result), 16)

    def test_md5_password(self):
        mod = self._mod()
        self.assertEqual(mod.md5_password("19810101"), "794d89deb8f6ff87c4a019ee65b15576")

    def test_sha256_with_sn(self):
        mod = self._mod()
        result = mod.sha256_with_sn("19810101", "HWTC12345678")
        self.assertEqual(len(result), 16)
        self.assertEqual(result, mod.sha256_with_sn("19810101", "HWTC12345678"))

    def test_sha256_sn_only(self):
        mod = self._mod()
        result = mod.sha256_sn_only("HWTC12345678")
        self.assertEqual(len(result), 16)

    def test_hmac_sha256_password(self):
        mod = self._mod()
        result = mod.hmac_sha256_password("19810101", "testkey")
        self.assertEqual(len(result), 16)

    def test_validate_date(self):
        mod = self._mod()
        self.assertTrue(mod.validate_date("19810101"))
        self.assertFalse(mod.validate_date("notadate"))

    def test_generate_all_passwords_no_sn(self):
        mod = self._mod()
        passwords = mod.generate_all_passwords("19810101")
        self.assertGreaterEqual(len(passwords), 10)
        self.assertEqual(passwords[0]["password"], "364ce967beff355b")

    def test_generate_all_passwords_with_sn(self):
        mod = self._mod()
        passwords = mod.generate_all_passwords("19810101", serial_number="HWTC12345678")
        methods = [p["method"] for p in passwords]
        self.assertTrue(any("Serial number" in m for m in methods))
        self.assertTrue(any("SN" in m for m in methods))

    def test_generate_all_passwords_with_key(self):
        mod = self._mod()
        passwords = mod.generate_all_passwords("19810101", aes_key="mykey123")
        methods = [p["method"] for p in passwords]
        self.assertTrue(any("HMAC" in m for m in methods))

    def test_all_passwords_have_required_keys(self):
        mod = self._mod()
        passwords = mod.generate_all_passwords("19810101", serial_number="SN123")
        for p in passwords:
            self.assertIn("password", p)
            self.assertIn("method", p)
            self.assertIn("feature", p)
            self.assertIn("priority", p)

    def test_factory_dates_constant(self):
        mod = self._mod()
        dates = [d[0] for d in mod.FACTORY_DATES]
        self.assertIn("19810101", dates)
        self.assertIn("19700101", dates)

    def test_default_passwords_includes_admintelecom(self):
        mod = self._mod()
        pwds = [p[0] for p in mod.DEFAULT_PASSWORDS]
        self.assertIn("admintelecom", pwds)
        self.assertIn("admin", pwds)
        self.assertIn("adminHW", pwds)

    def test_firmware_constants(self):
        mod = self._mod()
        self.assertEqual(mod.AES_KEY, "Df7!ui%s9(lmV1L8")
        self.assertEqual(mod.DEFAULT_SN, "4857544347020CB1")
        self.assertEqual(mod.DEFAULT_SN_ASCII, "HWTC47020CB1")
        self.assertEqual(mod.MEGACABLE_ADMIN_USER, "Mega_gpon")
        self.assertEqual(mod.MEGACABLE_ADMIN_PASSWORD, "admintelecom")

    def test_asc_unvisible(self):
        mod = self._mod()
        # '!' (0x21) decodes to 0x00
        self.assertEqual(mod.asc_unvisible("!"), b"\x00")
        # '~' (0x7E) decodes to 0x1E
        self.assertEqual(mod.asc_unvisible("~"), b"\x1e")
        # '@' (0x40) decodes to 0x1F
        self.assertEqual(mod.asc_unvisible("@"), b"\x1f")

    def test_asc_visible(self):
        mod = self._mod()
        # 0x00 encodes to '!' (0x21)
        self.assertEqual(mod.asc_visible(b"\x00"), "!")
        # 0x1E encodes to '~' (because 0x1E+0x21=0x3F='?' -> '~')
        self.assertEqual(mod.asc_visible(b"\x1e"), "~")

    def test_asc_roundtrip(self):
        mod = self._mod()
        # Encode then decode should preserve data (for values 0x00-0x5D except 0x5D)
        original = bytes(range(0x5D))  # 0 to 92
        encoded = mod.asc_visible(original)
        decoded = mod.asc_unvisible(encoded)
        # Note: 0x1E and 0x5D both encode to '~', decode gives 0x1E
        expected = bytearray(original)
        expected[0x5D - 1] = expected[0x5D - 1]  # 0x5C stays 0x5C
        self.assertEqual(decoded, bytes(expected))

    def test_cli_mode_output(self):
        """Verify cli_mode prints results without error."""
        import io
        from contextlib import redirect_stdout
        mod = self._mod()
        buf = io.StringIO()
        with redirect_stdout(buf):
            mod.cli_mode("19810101", None, None)
        output = buf.getvalue()
        self.assertIn("364ce967beff355b", output)
        self.assertIn("admin", output)

    def test_cli_mode_with_sn(self):
        """Verify cli_mode with SN prints SN-based passwords."""
        import io
        from contextlib import redirect_stdout
        mod = self._mod()
        buf = io.StringIO()
        with redirect_stdout(buf):
            mod.cli_mode("19810101", "HWTC12345678", None)
        output = buf.getvalue()
        self.assertIn("HWTC12345678", output)
        self.assertIn("12345678", output)  # Last 8 chars
