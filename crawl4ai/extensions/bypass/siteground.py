"""
SiteGround CAPTCHA (Proof-of-Work) bypass.

SiteGround's security plugin presents a JavaScript-based proof-of-work
challenge.  This module:

* Detects SiteGround CAPTCHA responses (:func:`is_sg_captcha_response`)
* Solves the SHA-1 proof-of-work challenge (:func:`solve_sg_pow`)
* Submits the solution to obtain a bypass cookie (:func:`solve_sg_captcha`)
"""

from __future__ import annotations

import base64
import hashlib
import logging
import re
import struct
import time

import requests

__all__ = [
    "solve_sg_pow",
    "solve_sg_captcha",
    "is_sg_captcha_response",
]

log = logging.getLogger("crawl4ai.extensions.bypass.siteground")

_SG_CHALLENGE_RE = re.compile(r'const\s+sgchallenge\s*=\s*"([^"]+)"')
_SG_SUBMIT_RE = re.compile(r'const\s+sgsubmit_url\s*=\s*"([^"]+)"')
_SG_MAX_ATTEMPTS = 10_000_000


def _counter_to_bytes(c: int) -> bytes:
    """Encode *c* as big-endian minimal-length bytes (matches SG JS)."""
    if c == 0:
        return b"\x00"
    if c > 0xFFFFFF:
        return c.to_bytes(4, "big")
    if c > 0xFFFF:
        return c.to_bytes(3, "big")
    if c > 0xFF:
        return c.to_bytes(2, "big")
    return c.to_bytes(1, "big")


def solve_sg_pow(challenge: str) -> tuple[str, int] | None:
    """Solve a SiteGround Proof-of-Work challenge.

    *challenge* is the value of ``sgchallenge`` from the captcha page
    (e.g. ``"20:timestamp:token:hash:"``).

    Returns ``(base64_solution, counter)`` on success or ``None``.
    """
    try:
        complexity = int(challenge.split(":")[0])
    except (ValueError, IndexError):
        return None
    if complexity < 1 or complexity > 32:
        return None

    challenge_bytes = challenge.encode("utf-8")
    for c in range(_SG_MAX_ATTEMPTS):
        data = challenge_bytes + _counter_to_bytes(c)
        h = hashlib.sha1(data).digest()
        first_word = struct.unpack(">I", h[:4])[0]
        if first_word >> (32 - complexity) == 0:
            return base64.b64encode(data).decode(), c
    return None


def solve_sg_captcha(
    session: requests.Session,
    base_url: str,
    target_path: str = "/",
    timeout: int = 30,
) -> bool:
    """Fetch a SiteGround captcha page, solve the PoW, and submit
    the solution so the session cookie is set for future requests.

    Returns ``True`` if the captcha was solved and the cookie was set.
    """
    quoted_path = requests.utils.quote(target_path, safe="/")
    captcha_url = (
        f"{base_url}/.well-known/sgcaptcha/"
        f"?r={quoted_path}&y=pow"
    )
    try:
        resp = session.get(captcha_url, timeout=timeout)
    except requests.RequestException:
        return False

    if resp.status_code != 200:
        return False

    cm = _SG_CHALLENGE_RE.search(resp.text)
    sm = _SG_SUBMIT_RE.search(resp.text)
    if not cm or not sm:
        return False

    challenge = cm.group(1)
    submit_path = sm.group(1)
    log.info("[SG-CAPTCHA] Solving PoW (complexity %s) …",
             challenge.split(":")[0])

    t0 = time.time()
    result = solve_sg_pow(challenge)
    if result is None:
        log.warning("[SG-CAPTCHA] Failed to solve PoW")
        return False

    solution, counter = result
    elapsed_ms = int((time.time() - t0) * 1000)
    log.info("[SG-CAPTCHA] Solved in %d ms (counter=%d)", elapsed_ms, counter)

    submit_url = f"{base_url}{submit_path}"
    sep = "&" if "?" in submit_url else "?"
    submit_url += (
        f"{sep}sol={requests.utils.quote(solution)}"
        f"&s={elapsed_ms}:{counter}"
    )
    try:
        session.get(submit_url, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return False

    has_cookie = any("_I_" in c.name for c in session.cookies)
    if has_cookie:
        log.info("[SG-CAPTCHA] Bypass cookie obtained")
    return has_cookie


def is_sg_captcha_response(resp: requests.Response) -> bool:
    """Return ``True`` if *resp* is a SiteGround CAPTCHA challenge page.

    Detects three variants:
    * ``SG-Captcha: challenge`` response header (canonical marker)
    * HTTP 202 with ``sgcaptcha`` in the first 500 bytes (inline challenge)
    * Any status with ``/.well-known/captcha/`` or ``sgcaptcha`` in the
      first 2 KB (SiteGround redirects / WAF-level block with CAPTCHA body)
    """
    if resp.headers.get("SG-Captcha") == "challenge":
        return True
    ct = resp.headers.get("Content-Type", "")
    if "html" not in ct.lower() and resp.status_code not in (202, 403):
        return False
    snippet = resp.text[:2000].lower()
    if "sgcaptcha" in snippet:
        return True
    if "/.well-known/captcha/" in snippet or "/.well-known/sgcaptcha/" in snippet:
        return True
    return False
