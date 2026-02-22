# Login Cookie Domain Fix

## Problem

After implementing the modular package structure and session expiry fixes, a new issue appeared:

```
02:08:17 [ERROR] The redirect to http://192.168.100.1/ returned the login page.
Session may not have been established.
Cookie after redirect: {'Cookie': 'body:Language:english:id=-1'}
```

The cookie value `'body:Language:english:id=-1'` is the **pre-authentication** cookie. After successful login, it should be updated to something like `'body:Language:english:id=12345'` with an actual session ID.

## Root Cause

The pre-login cookie was being set with an explicit `domain` parameter:

```python
session.cookies.set(
    "Cookie",
    "body:Language:english:id=-1",
    domain=host,  # ← This was the problem!
    path="/",
)
```

Where `host = "192.168.100.1"`.

### Why This Caused Issues

The `requests` library's cookie handling is very strict about cookie matching. When a cookie is set with an explicit `domain` parameter, the library will only update/replace that cookie if:
1. The cookie name matches
2. The domain matches **exactly**
3. The path matches

When the router's `/login.cgi` endpoint responds with a `Set-Cookie` header after successful authentication, it likely does NOT include an explicit domain attribute. According to HTTP cookie standards, when domain is omitted from Set-Cookie, the cookie defaults to the exact host that sent it.

This means:
- Our pre-login cookie: `name="Cookie", domain="192.168.100.1", path="/"`
- Router's auth cookie: `name="Cookie", domain=None (defaults to host), path="/"`

These are treated as **different cookies** by the requests library, so the router's Set-Cookie doesn't update our pre-login cookie. The session cookie jar ends up with:
- The old pre-login cookie with `domain="192.168.100.1"` and value `"body:Language:english:id=-1"`
- Possibly a new cookie without domain that wasn't being used

## Solution

Remove the `domain` parameter when setting the pre-login cookie:

```python
session.cookies.set(
    "Cookie",
    "body:Language:english:id=-1",
    # No domain parameter - let it default to the request host
    path="/",
)
```

Now when the router sends `Set-Cookie: Cookie=body:Language:english:id=12345; path=/`, the requests library will properly update the cookie because the domain attributes match (both default to the host).

## Debug Logging Added

To help diagnose cookie issues in the future, added comprehensive logging after the login POST:

```python
# Debug: Log response headers and cookies from login.cgi
log.debug("login.cgi response status: %s", resp.status_code)
log.debug("login.cgi Set-Cookie headers: %s", resp.headers.get('Set-Cookie'))
log.debug("login.cgi response cookies: %s", dict(resp.cookies))
log.debug("Session cookies after login.cgi POST: %s", dict(session.cookies))
```

This shows:
1. Whether the login POST succeeded (status 200)
2. What Set-Cookie header the router sent
3. What cookies were in the response
4. What cookies are now in the session jar

## Expected Behavior After Fix

With `--debug` flag, you should see:

```
[DEBUG] login.cgi response status: 200
[DEBUG] login.cgi Set-Cookie headers: Cookie=body:Language:english:id=123456; path=/
[DEBUG] login.cgi response cookies: {'Cookie': 'body:Language:english:id=123456'}
[DEBUG] Session cookies after login.cgi POST: {'Cookie': 'body:Language:english:id=123456'}
```

And later:

```
[DEBUG] Cookies after following redirect: {'Cookie': 'body:Language:english:id=123456'}
[INFO] Login successful (HTTP 200, method=base64). Admin home: http://192.168.100.1/
```

No more "Cookie after redirect: {'Cookie': 'body:Language:english:id=-1'}" error!

## Files Changed

1. **crawler.py** (lines 343-349)
   - Removed `domain=host` parameter from cookie set
   - Added comment explaining why

2. **crawler.py** (lines 376-379)
   - Added debug logging for login response cookies

## Testing

To test with a real router:

```bash
python -m huawei_crawler --password YOUR_PASSWORD --debug
```

Look for the debug lines showing cookie values. The session should now establish correctly.

## Related Issues

This is related to the earlier fix for `is_session_expired()` false positives. Together, these fixes ensure:
1. Login properly establishes an authenticated session (cookie domain fix)
2. The crawler correctly identifies authenticated vs. expired sessions (session expiry fix)

Both were necessary for successful crawling.
