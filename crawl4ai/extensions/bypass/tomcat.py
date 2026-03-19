"""
Apache Tomcat IP-restriction detection.

Tomcat's documentation, examples, manager, and host-manager web applications
are restricted to localhost by default.  The response body contains a
distinctive phrase that identifies this type of block, which cannot be
bypassed by header rotation or cookie injection from an external IP.
"""

from __future__ import annotations

import requests

__all__ = ["is_tomcat_ip_restricted"]

_TOMCAT_IP_RESTRICTED_PHRASES = (
    "only accessible from a browser running on the same machine as tomcat",
    "by default the documentation web application is only accessible",
    "by default the manager is only accessible",
    "by default the host manager is only accessible",
    "by default the examples web application is only accessible",
)


def is_tomcat_ip_restricted(resp: requests.Response) -> bool:
    """Return ``True`` if *resp* is a Tomcat IP-restriction 403 page.

    Detecting it early lets the crawler skip pointless retries and record
    the page body for the crawl archive.
    """
    if resp.status_code not in (403, 401):
        return False
    ct = resp.headers.get("Content-Type", "")
    if "html" not in ct.lower():
        return False
    snippet = resp.text[:3000].lower()
    return any(phrase in snippet for phrase in _TOMCAT_IP_RESTRICTED_PHRASES)
