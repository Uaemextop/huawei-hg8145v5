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
# Tests for tools/challenge_generator.py
# ---------------------------------------------------------------------------

def _load_challenge_mod():
    """Helper to import challenge_generator module."""
    spec = importlib.util.spec_from_file_location(
        "challenge_generator",
        os.path.join(os.path.dirname(__file__), "..", "tools", "challenge_generator.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestChallengeGeneratorImports(unittest.TestCase):
    """Test that challenge_generator module can be imported."""

    def test_import_module(self):
        mod = _load_challenge_mod()
        self.assertTrue(hasattr(mod, "sha256_challenge"))
        self.assertTrue(hasattr(mod, "md5_challenge"))
        self.assertTrue(hasattr(mod, "generate_all_challenges"))
        self.assertTrue(hasattr(mod, "format_date"))


class TestSHA256Challenge(unittest.TestCase):
    """Test the primary SHA-256 challenge algorithm."""

    def _get_mod(self):
        return _load_challenge_mod()

    def test_sha256_19810101(self):
        mod = self._get_mod()
        result = mod.sha256_challenge("19810101")
        self.assertEqual(
            result,
            "364ce967beff355bea79d2f81213ffa5fd1f51760c7d9c7714b1b6066ebfd1e8",
        )

    def test_sha256_20260221(self):
        mod = self._get_mod()
        result = mod.sha256_challenge("20260221")
        self.assertEqual(
            result,
            "96eb2f1c1ff60cc50c5101a48669c76306e5a732ef34fc7aae6616ae424cd534",
        )

    def test_sha256_truncated_16(self):
        mod = self._get_mod()
        result = mod.sha256_challenge("19810101", length=16)
        self.assertEqual(result, "364ce967beff355b")

    def test_sha256_truncated_8(self):
        mod = self._get_mod()
        result = mod.sha256_challenge("19810101", length=8)
        self.assertEqual(result, "364ce967")


class TestMD5Challenge(unittest.TestCase):
    """Test the MD5 challenge variant."""

    def _get_mod(self):
        return _load_challenge_mod()

    def test_md5_19810101(self):
        mod = self._get_mod()
        result = mod.md5_challenge("19810101")
        self.assertEqual(result, "794d89deb8f6ff87c4a019ee65b15576")


class TestDateUtils(unittest.TestCase):
    """Test date utility functions."""

    def _get_mod(self):
        return _load_challenge_mod()

    def test_parse_date_valid(self):
        mod = self._get_mod()
        from datetime import date
        result = mod.parse_date("19810101")
        self.assertEqual(result, date(1981, 1, 1))

    def test_parse_date_invalid(self):
        mod = self._get_mod()
        result = mod.parse_date("invalid")
        self.assertIsNone(result)

    def test_format_date(self):
        mod = self._get_mod()
        from datetime import date
        result = mod.format_date(date(2026, 2, 21))
        self.assertEqual(result, "20260221")

    def test_format_date_matches_firmware_format(self):
        """Verify format matches firmware %4u%02u%02u."""
        mod = self._get_mod()
        from datetime import date
        # Single-digit month and day must be zero-padded
        result = mod.format_date(date(1981, 1, 1))
        self.assertEqual(result, "19810101")

    def test_date_range(self):
        mod = self._get_mod()
        dates = list(mod.date_range("20260220", "20260222"))
        self.assertEqual(dates, ["20260220", "20260221", "20260222"])


class TestGenerateAllChallenges(unittest.TestCase):
    """Test the combined challenge generator."""

    def _get_mod(self):
        return _load_challenge_mod()

    def test_returns_multiple_methods(self):
        mod = self._get_mod()
        results = mod.generate_all_challenges("19810101")
        # At least SHA-256 + MD5 + 4 suffix variants = 6
        self.assertGreaterEqual(len(results), 6)

    def test_primary_method_is_sha256(self):
        mod = self._get_mod()
        results = mod.generate_all_challenges("19810101")
        self.assertEqual(results[0]["method"], "SHA-256(date)")

    def test_all_results_have_required_keys(self):
        mod = self._get_mod()
        results = mod.generate_all_challenges("19810101")
        for r in results:
            self.assertIn("method", r)
            self.assertIn("full_hash", r)
            self.assertIn("challenge_16", r)
            self.assertIn("challenge_8", r)

    def test_challenge_16_is_prefix_of_full(self):
        mod = self._get_mod()
        results = mod.generate_all_challenges("19810101")
        for r in results:
            self.assertTrue(r["full_hash"].startswith(r["challenge_16"]))

    def test_known_dates_constant_exists(self):
        mod = self._get_mod()
        self.assertIn("19810101", mod.KNOWN_DATES)
        self.assertIn("19700101", mod.KNOWN_DATES)
