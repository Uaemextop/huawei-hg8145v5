"""Tests for the security audit tool.

These tests mock HTTP responses to verify vulnerability detection logic
without needing an actual router.
"""

import json
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

  Form.addParameter('PassWord', base64encode(Password.value));

  var cookie2 = "Cookie=body:Language:english:id=-1;path=/";
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
