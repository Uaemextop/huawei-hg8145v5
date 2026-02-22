# Cookie Duplication Fix for Login Session

## The Persistent Problem

Even after removing the `domain=` parameter, login still failed with:
```
Cookie after redirect: {'Cookie': 'body:Language:english:id=-1'}
```

The cookie remained stuck at the pre-login value.

## Root Cause: Hidden Duplicate Cookies

The issue was **duplicate cookie entries** in the session cookie jar that were hidden by `dict(session.cookies)`.

### How Duplicates Occur

1. We set pre-login cookie without domain:
   ```python
   session.cookies.set("Cookie", "body:Language:english:id=-1", path="/")
   # Creates: Cookie[name=Cookie, value=...id=-1, domain='', path=/]
   ```

2. Router responds with Set-Cookie header including domain:
   ```
   Set-Cookie: Cookie=body:Language:english:id=12345; path=/; domain=192.168.100.1
   ```

3. Requests library adds this as a NEW cookie (different domain attribute):
   ```python
   # Now we have TWO cookies:
   # Cookie[name=Cookie, value=...id=-1, domain='', path=/]      ← pre-login
   # Cookie[name=Cookie, value=...id=12345, domain='192.168.100.1', path=/]  ← authenticated
   ```

4. When calling `dict(session.cookies)`, it only shows one entry (hiding the duplicate)

5. When making subsequent requests, the requests library might use the WRONG cookie (the pre-login one)

### Verification Test

```python
import requests

session = requests.Session()
session.cookies.set('Cookie', 'body:Language:english:id=-1', path='/')
session.cookies.set('Cookie', 'body:Language:english:id=12345', path='/', domain='192.168.100.1')

print(f"Number of cookies: {len(list(session.cookies))}")  # Shows: 2
print(f"dict(cookies): {dict(session.cookies)}")            # Shows: {'Cookie': '...'}  ← Only one!

# Trying to access causes CookieConflictError:
try:
    for cookie in session.cookies:
        print(f"Cookie: {cookie.name}={cookie.value}, domain={cookie.domain!r}")
except Exception as e:
    print(f"Error: {e}")
```

Output shows 2 cookies exist but `dict()` hides the duplication!

## The Solution: Two-Step Fix

### Step 1: Clear Cookies Before Setting Pre-Login Cookie

```python
# Before setting the pre-login cookie, clear any existing cookies
session.cookies.clear()
session.cookies.set(
    "Cookie",
    "body:Language:english:id=-1",
    path="/",
)
```

This ensures we start fresh without any stale cookies that could cause conflicts.

### Step 2: Deduplicate After Login POST

```python
# After the login POST response, deduplicate any duplicate "Cookie" entries
cookie_list = list(session.cookies)
if len(cookie_list) > 1:
    cookie_entries = [c for c in cookie_list if c.name == "Cookie"]
    if len(cookie_entries) > 1:
        log.debug("Found %d duplicate 'Cookie' entries, keeping only the last one", len(cookie_entries))
        # Remove all but the last one (most recent, which should be the authenticated one)
        for cookie_to_remove in cookie_entries[:-1]:
            session.cookies.clear(cookie_to_remove.domain, cookie_to_remove.path, cookie_to_remove.name)
```

This removes the pre-login cookie, keeping only the authenticated cookie from the router's response.

## Why This Wasn't Obvious

1. **Hidden by dict()**: Calling `dict(session.cookies)` only shows one cookie, making it appear there's no duplication

2. **No immediate error**: The CookieConflictError only occurs in certain operations, not just from having duplicates

3. **Inconsistent behavior**: Sometimes the wrong cookie is used, sometimes the right one - depends on internal ordering

4. **Domain matching subtleties**: Cookies with `domain=''` vs `domain='192.168.100.1'` are treated as different cookies by the requests library

## Expected Behavior After Fix

With `--debug` flag, you should now see:

```
[DEBUG] Session cookies after login.cgi POST: {'Cookie': 'body:Language:english:id=12345'}
[DEBUG] Cookies after following redirect: {'Cookie': 'body:Language:english:id=12345'}
[INFO] Login successful (HTTP 200, method=base64)
```

The cookie value changes from `-1` (pre-login) to actual session ID (authenticated).

## Files Changed

1. **crawler.py**
   - Line 347: Added `session.cookies.clear()` before setting pre-login cookie
   - Lines 384-396: Added cookie deduplication after login POST

2. **huawei_crawler/auth/login.py**
   - Line 193: Added `session.cookies.clear()` before setting pre-login cookie
   - Lines 230-242: Added cookie deduplication after login POST

## Related Fixes

This completes the cookie handling fixes:
1. **Initial fix**: Removed `domain=` parameter (commit 37d7192)
2. **This fix**: Clear cookies and deduplicate (commit 7008d84)

Together, these ensure:
- No domain mismatch between our cookie and router's cookie
- No duplicate cookies that could cause wrong cookie to be used
- Clean session state for successful authentication
