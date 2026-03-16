"""
Amazon S3 / CloudFront private-bucket detection.

Private S3 buckets (with Block Public Access enabled) return HTTP 403
with ``server: AmazonS3`` and an XML ``<Error><Code>AccessDenied</Code>``
body.  This block is enforced at the bucket-policy / account level and
**cannot be bypassed** by any HTTP header, credential, or URL trick from
an external, unauthenticated client.
"""

from __future__ import annotations

import requests

__all__ = ["is_s3_access_denied"]


def is_s3_access_denied(resp: requests.Response) -> bool:
    """Return ``True`` if *resp* is an Amazon S3 ``AccessDenied`` error.

    Detecting it immediately lets the crawler skip pointless
    header-rotation retries and record the XML response body for the archive.
    """
    if resp.status_code != 403:
        return False
    server = resp.headers.get("server", "") or resp.headers.get("Server", "")
    if "amazons3" not in server.lower():
        return False
    ct = resp.headers.get("Content-Type", resp.headers.get("content-type", ""))
    if "xml" not in ct.lower():
        return False
    snippet = resp.text[:512]
    return "<Code>AccessDenied</Code>" in snippet or "AccessDenied" in snippet
