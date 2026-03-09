"""
AWS Signature Version 4 utilities for pre-signed S3 URL analysis.

This module implements the canonical-request / string-to-sign reconstruction
defined in the `AWS Signature Version 4`_ specification, scoped to the
``X-Amz-*`` query-parameter variant used for pre-signed S3 GET URLs returned
by the LMSA ``rescueDevice/getResource.jhtml`` API.

Typical use-case (analysis / verification)::

    parsed = parse_presigned_s3_url(url)
    if parsed:
        cr  = presigned_canonical_request(parsed)
        sts = presigned_string_to_sign(parsed, cr)
        # To verify (requires secret key):
        sig = compute_presigned_signature(secret_key, parsed)
        print(sig == parsed["signature"])   # True when secret_key is correct

.. _AWS Signature Version 4:
   https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
"""

from __future__ import annotations

import hashlib
import hmac
import re
import sys
import urllib.parse
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Algorithm identifier used by the LMSA S3 bucket.
AWS4_ALGORITHM = "AWS4-HMAC-SHA256"

#: Payload hash used for pre-signed GET requests (no request body).
_UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD"

#: Names of the query parameters that carry AWS V4 pre-signing data.
_PRESIGN_PARAMS = frozenset({
    "X-Amz-Algorithm",
    "X-Amz-Credential",
    "X-Amz-Date",
    "X-Amz-Expires",
    "X-Amz-SignedHeaders",
    "X-Amz-Signature",
    "X-Amz-Security-Token",
})

# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def is_presigned_s3_url(url: str) -> bool:
    """Return ``True`` when *url* contains AWS V4 pre-signing parameters.

    A pre-signed URL must carry at minimum ``X-Amz-Algorithm``,
    ``X-Amz-Credential``, ``X-Amz-Date``, and ``X-Amz-Signature``.

    Example::

        >>> is_presigned_s3_url(
        ...     "https://rsddownload-secure.lenovo.com/file.zip"
        ...     "?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc123"
        ... )
        True
    """
    qs = urllib.parse.urlparse(url).query
    params = {k for k, _ in urllib.parse.parse_qsl(qs, keep_blank_values=True)}
    required = {"X-Amz-Algorithm", "X-Amz-Credential",
                "X-Amz-Date", "X-Amz-Signature"}
    return required.issubset(params)


def parse_presigned_s3_url(url: str) -> Optional[dict]:
    """Parse an AWS V4 pre-signed S3 URL into its structural components.

    Returns ``None`` when *url* is not a valid pre-signed URL (missing
    required ``X-Amz-*`` parameters or an unparseable credential scope).

    The returned dict has the following keys:

    ``algorithm``
        The signing algorithm (``"AWS4-HMAC-SHA256"``).
    ``host``
        The S3 bucket hostname (e.g. ``"rsddownload-secure.lenovo.com"``).
    ``path``
        The URL-encoded object key / path (e.g. ``"/firmware.zip"``).
    ``date``
        ISO-8601 timestamp used during signing (e.g. ``"20260304T032129Z"``).
    ``date_short``
        8-character date prefix of *date* (e.g. ``"20260304"``).
    ``access_key_id``
        AWS Access Key ID extracted from ``X-Amz-Credential``.
    ``region``
        AWS region (e.g. ``"us-east-1"``).
    ``service``
        AWS service (``"s3"``).
    ``credential_scope``
        Full credential scope string
        ``"<date_short>/<region>/<service>/aws4_request"``.
    ``signed_headers``
        Semicolon-separated list of signed header names (e.g. ``"host"``).
    ``expires``
        Pre-signed URL validity in seconds (integer).
    ``signature``
        The hex-encoded HMAC-SHA256 signature value.
    ``security_token``
        Optional STS session token (``None`` when not present).
    ``extra_params``
        Any additional query parameters not part of the AWS signing scheme.
    """
    parsed = urllib.parse.urlparse(url)
    qs_dict: dict[str, str] = dict(
        urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    )

    # Validate required parameters
    for key in ("X-Amz-Algorithm", "X-Amz-Credential",
                "X-Amz-Date", "X-Amz-SignedHeaders",
                "X-Amz-Expires", "X-Amz-Signature"):
        if key not in qs_dict:
            return None

    # Parse credential: AKID/date/region/service/aws4_request
    credential = qs_dict["X-Amz-Credential"]
    cred_match = re.fullmatch(
        r"([^/]+)/(\d{8})/([^/]+)/([^/]+)/aws4_request",
        credential,
    )
    if not cred_match:
        return None

    access_key_id, date_short, region, service = cred_match.groups()
    date = qs_dict["X-Amz-Date"]

    # Extra params: everything not in the standard pre-sign set
    extra_params = {
        k: v for k, v in qs_dict.items() if k not in _PRESIGN_PARAMS
    }

    return {
        "algorithm":        qs_dict["X-Amz-Algorithm"],
        "host":             parsed.netloc,
        "path":             parsed.path,
        "date":             date,
        "date_short":       date_short,
        "access_key_id":    access_key_id,
        "region":           region,
        "service":          service,
        "credential_scope": f"{date_short}/{region}/{service}/aws4_request",
        "signed_headers":   qs_dict["X-Amz-SignedHeaders"],
        "expires":          int(qs_dict["X-Amz-Expires"]),
        "signature":        qs_dict["X-Amz-Signature"],
        "security_token":   qs_dict.get("X-Amz-Security-Token"),
        "extra_params":     extra_params,
        # Keep the original query dict for canonical request reconstruction
        "_qs":              qs_dict,
    }


def presigned_canonical_request(parsed: dict) -> str:
    """Build the canonical request string for a pre-signed S3 URL.

    Implements the ``Task 1: Create a canonical request`` step of AWS
    Signature Version 4 for the pre-signed URL variant (method = ``GET``,
    payload hash = ``UNSIGNED-PAYLOAD``).

    The canonical request format is::

        HTTPMethod\\n
        CanonicalURI\\n
        CanonicalQueryString\\n
        CanonicalHeaders\\n
        SignedHeaders\\n
        HashedPayload

    Where *CanonicalQueryString* contains all ``X-Amz-*`` params **except**
    ``X-Amz-Signature``, sorted alphabetically by key name.  Each key and
    value is percent-encoded using ``urllib.parse.quote(safe="")``.

    Parameters
    ----------
    parsed:
        Dict returned by :func:`parse_presigned_s3_url`.
    """
    # --- Canonical URI ---
    # URI-encode the path; forward slashes are preserved.
    canonical_uri = urllib.parse.quote(parsed["path"], safe="/-._~")
    if not canonical_uri:
        canonical_uri = "/"

    # --- Canonical query string ---
    # All query params except X-Amz-Signature, sorted by key then value.
    qs_items = sorted(
        (k, v) for k, v in parsed["_qs"].items() if k != "X-Amz-Signature"
    )
    canonical_qs = "&".join(
        f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}"
        for k, v in qs_items
    )

    # --- Canonical headers ---
    # Only the headers listed in X-Amz-SignedHeaders are included.
    # For pre-signed GET URLs the only signed header is "host".
    signed_hdr_names = [h.strip() for h in parsed["signed_headers"].split(";")]
    canonical_headers_lines: list[str] = []
    for hdr in sorted(signed_hdr_names):
        if hdr == "host":
            canonical_headers_lines.append(f"host:{parsed['host']}")
        # Additional signed headers (e.g. x-amz-security-token) would be
        # appended here if present.
    canonical_headers = "\n".join(canonical_headers_lines) + "\n"

    # --- Signed headers string (same as X-Amz-SignedHeaders param) ---
    signed_headers_str = ";".join(sorted(signed_hdr_names))

    # --- Hashed payload ---
    # Pre-signed S3 GET requests always use the literal string
    # "UNSIGNED-PAYLOAD" rather than the SHA-256 of an empty body.
    hashed_payload = _UNSIGNED_PAYLOAD

    return "\n".join([
        "GET",
        canonical_uri,
        canonical_qs,
        canonical_headers,
        signed_headers_str,
        hashed_payload,
    ])


def presigned_string_to_sign(parsed: dict, canonical_request: str) -> str:
    """Build the string-to-sign for a pre-signed S3 URL.

    Implements ``Task 2: Create a string to sign`` of AWS Signature V4::

        Algorithm\\n
        RequestDateTime\\n
        CredentialScope\\n
        HexEncode(Hash(CanonicalRequest))

    Parameters
    ----------
    parsed:
        Dict returned by :func:`parse_presigned_s3_url`.
    canonical_request:
        The canonical request string from :func:`presigned_canonical_request`.
    """
    cr_hash = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    return "\n".join([
        parsed["algorithm"],
        parsed["date"],
        parsed["credential_scope"],
        cr_hash,
    ])


def compute_signing_key(
    secret_key: str,
    date_short: str,
    region: str,
    service: str,
) -> bytes:
    """Derive the AWS V4 signing key via the HMAC key-derivation chain.

    Implements ``Task 3: Calculate the signature`` (key derivation step)::

        kDate    = HMAC("AWS4" + secret_key, date_short)
        kRegion  = HMAC(kDate,    region)
        kService = HMAC(kRegion,  service)
        kSigning = HMAC(kService, "aws4_request")

    Parameters
    ----------
    secret_key:
        The AWS Secret Access Key (plaintext, not encoded).
    date_short:
        8-character UTC date string, e.g. ``"20260304"``.
    region:
        AWS region name, e.g. ``"us-east-1"``.
    service:
        AWS service name, e.g. ``"s3"``.

    Returns
    -------
    bytes
        The derived signing key (32 bytes for SHA-256).
    """
    def _hmac(key: bytes, data: str) -> bytes:
        return hmac.new(key, data.encode("utf-8"), hashlib.sha256).digest()

    k_date    = _hmac(b"AWS4" + secret_key.encode("utf-8"), date_short)
    k_region  = _hmac(k_date,    region)
    k_service = _hmac(k_region,  service)
    k_signing = _hmac(k_service, "aws4_request")
    return k_signing


def compute_presigned_signature(
    secret_key: str,
    parsed: dict,
) -> str:
    """Compute the expected AWS V4 signature for a pre-signed S3 URL.

    This reproduces the ``X-Amz-Signature`` value that AWS would produce
    given the correct Secret Access Key.  Use it to verify that a captured
    pre-signed URL is authentic or to generate a fresh signature when
    re-signing a URL.

    Parameters
    ----------
    secret_key:
        The AWS Secret Access Key corresponding to the Access Key ID in the
        ``X-Amz-Credential`` query parameter.
    parsed:
        Dict returned by :func:`parse_presigned_s3_url`.

    Returns
    -------
    str
        Lowercase hex-encoded HMAC-SHA256 signature (64 hex characters).
    """
    cr  = presigned_canonical_request(parsed)
    sts = presigned_string_to_sign(parsed, cr)
    signing_key = compute_signing_key(
        secret_key,
        parsed["date_short"],
        parsed["region"],
        parsed["service"],
    )
    sig_bytes = hmac.new(
        signing_key, sts.encode("utf-8"), hashlib.sha256
    ).digest()
    return sig_bytes.hex()


def curl_command(url: str) -> Optional[str]:
    """Return a ready-to-run ``curl`` command that downloads *url*.

    For pre-signed S3 URLs the pre-signing query parameters are already
    embedded in the URL, so no extra headers are required — ``curl`` just
    needs the URL itself.  The command uses ``-L`` (follow redirects) and
    ``-O`` (write to a file named after the remote object key).

    Returns ``None`` when *url* is not a recognised HTTPS URL.

    Example output::

        curl -L -O "https://rsddownload-secure.lenovo.com/firmware.zip
        ?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=…"

    For non-pre-signed URLs on the same host the command is identical in
    structure but will return HTTP 403 (private bucket requires signing).
    """
    if not url.startswith(("http://", "https://")):
        return None
    # Escape any double-quotes inside the URL (rare but safe practice)
    safe_url = url.replace('"', '\\"')
    return f'curl -L -O "{safe_url}"'


def print_analysis(url: str, secret_key: str = "", *, file=None) -> None:
    """Print a human-readable AWS Signature V4 analysis for *url*.

    Writes to *file* (default ``sys.stdout``).

    The analysis covers every step of the signature calculation:

    1. Parsed URL components (credential scope, access key ID, date …)
    2. Canonical request (``Task 1`` of the AWS spec)
    3. String-to-sign (``Task 2``)
    4. Signing-key derivation chain (``Task 3`` — no secret needed to show
       the derivation *structure*)
    5. Expected signature — only when *secret_key* is supplied
    6. Signature match result — only when *secret_key* is supplied
    7. Ready-to-run ``curl`` command

    Parameters
    ----------
    url:
        The pre-signed (or plain) S3 URL to analyse.
    secret_key:
        Optional AWS Secret Access Key.  When supplied the expected
        ``X-Amz-Signature`` is computed and compared against the captured
        value in *url*.
    file:
        Output stream (default ``sys.stdout``).
    """
    out = file or sys.stdout

    def _p(line: str = "") -> None:
        print(line, file=out)

    _p("=" * 72)
    _p("AWS Signature V4 — Pre-Signed URL Analysis")
    _p("=" * 72)
    _p(f"URL: {url}")
    _p()

    parsed = parse_presigned_s3_url(url)
    if parsed is None:
        _p("[!] Not a valid pre-signed S3 URL (missing required X-Amz-* params)")
        cmd = curl_command(url)
        if cmd:
            _p()
            _p("curl command:")
            _p(f"  {cmd}")
        _p("=" * 72)
        return

    # ------------------------------------------------------------------ #
    # 1. Parsed components
    # ------------------------------------------------------------------ #
    _p("1. PARSED COMPONENTS")
    _p("-" * 40)
    _p(f"  Host            : {parsed['host']}")
    _p(f"  Object key      : {parsed['path']}")
    _p(f"  Algorithm       : {parsed['algorithm']}")
    _p(f"  Access Key ID   : {parsed['access_key_id']}")
    _p(f"  Region          : {parsed['region']}")
    _p(f"  Service         : {parsed['service']}")
    _p(f"  Credential scope: {parsed['credential_scope']}")
    _p(f"  Date (ISO-8601) : {parsed['date']}")
    _p(f"  Expires         : {parsed['expires']} s "
       f"({parsed['expires'] // 3600}h {(parsed['expires'] % 3600) // 60}m)")
    _p(f"  Signed headers  : {parsed['signed_headers']}")
    if parsed["security_token"]:
        _p(f"  Security token  : {parsed['security_token'][:20]}…")
    _p(f"  Captured sig    : {parsed['signature']}")
    _p()

    # ------------------------------------------------------------------ #
    # 2. Canonical request  (Task 1)
    # ------------------------------------------------------------------ #
    cr = presigned_canonical_request(parsed)
    cr_hash = hashlib.sha256(cr.encode()).hexdigest()
    _p("2. CANONICAL REQUEST  (Task 1 — AWS Signature V4 spec)")
    _p("-" * 40)
    _p(cr)
    _p()
    _p(f"  SHA-256(CanonicalRequest) = {cr_hash}")
    _p()

    # ------------------------------------------------------------------ #
    # 3. String-to-sign  (Task 2)
    # ------------------------------------------------------------------ #
    sts = presigned_string_to_sign(parsed, cr)
    _p("3. STRING-TO-SIGN  (Task 2)")
    _p("-" * 40)
    _p(sts)
    _p()

    # ------------------------------------------------------------------ #
    # 4. Signing-key derivation  (Task 3)
    # ------------------------------------------------------------------ #
    _p("4. SIGNING KEY DERIVATION  (Task 3)")
    _p("-" * 40)
    _p(f"  kDate    = HMAC( b'AWS4' + secret_key,       '{parsed['date_short']}' )")
    _p(f"  kRegion  = HMAC( kDate,                      '{parsed['region']}' )")
    _p(f"  kService = HMAC( kRegion,                    '{parsed['service']}' )")
    _p( "  kSigning = HMAC( kService,                   'aws4_request' )")
    _p( "  Signature = HEX( HMAC( kSigning, StringToSign ) )")
    _p()

    # ------------------------------------------------------------------ #
    # 5 & 6. Computed signature + match (only when secret_key is given)
    # ------------------------------------------------------------------ #
    if secret_key:
        computed = compute_presigned_signature(secret_key, parsed)
        match = computed == parsed["signature"]
        _p("5. COMPUTED SIGNATURE")
        _p("-" * 40)
        _p(f"  Computed : {computed}")
        _p(f"  Captured : {parsed['signature']}")
        _p(f"  Match    : {'✓ YES — secret key is correct' if match else '✗ NO — wrong secret key'}")
        _p()

    # ------------------------------------------------------------------ #
    # 7. curl command
    # ------------------------------------------------------------------ #
    _p("curl COMMAND (downloads the file — valid while URL has not expired)")
    _p("-" * 40)
    _p(f"  {curl_command(url)}")
    _p("=" * 72)
