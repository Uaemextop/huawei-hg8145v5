"""Backend framework handler – probes framework-specific routes and handles tokens."""
from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from .base import BaseHandler, HandlerResult

if TYPE_CHECKING:
    import requests

log = logging.getLogger(__name__)

__all__ = ["BackendFrameworkHandler"]

_BACKEND_TYPES = frozenset({"django", "flask", "rails", "laravel", "aspnet"})


class BackendFrameworkHandler(BaseHandler):
    """Probe API routes and handle CSRF / token mechanics for backend frameworks.

    Supports Django, Flask, Rails, Laravel, and ASP.NET.
    """

    name = "backend_framework"

    def can_handle(self, detection: dict) -> bool:
        """Return True for any known backend-framework detection."""
        return detection.get("type", "") in _BACKEND_TYPES

    def apply(
        self,
        url: str,
        session: "requests.Session",
        response: "requests.Response | None",
        detection: dict,
    ) -> HandlerResult:
        """Apply framework-specific probes and token handling."""
        fw = detection.get("type", "")
        actions: list[str] = []
        extra_urls: list[str] = []
        extra_headers: dict = {}

        try:
            if fw == "django":
                _handle_django(url, session, response, actions,
                               extra_urls, extra_headers)

            elif fw == "flask":
                _handle_flask(url, actions, extra_urls)

            elif fw == "rails":
                _handle_rails(url, session, response, actions,
                              extra_urls, extra_headers)

            elif fw == "laravel":
                _handle_laravel(url, session, response, actions,
                                extra_urls, extra_headers)

            elif fw == "aspnet":
                _handle_aspnet(url, response, actions,
                               extra_urls, extra_headers)

        except Exception:
            log.debug(
                "BackendFrameworkHandler error for %s", url, exc_info=True
            )
            actions.append(f"Error processing {fw} detection")

        return HandlerResult(
            handler=self.name,
            actions_taken=actions,
            extra_urls=extra_urls,
            extra_headers=extra_headers,
            recommended_config={},
        )


# ------------------------------------------------------------------
# Per-framework helpers
# ------------------------------------------------------------------

def _handle_django(
    url: str,
    session: "requests.Session",
    response: "requests.Response | None",
    actions: list[str],
    extra_urls: list[str],
    extra_headers: dict,
) -> None:
    probes = ["/admin/", "/api/", "/static/"]
    for p in probes:
        extra_urls.append(urljoin(url, p))
    actions.append(f"Probing Django endpoints: {', '.join(probes)}")

    # CSRF token from cookie
    csrf = _cookie_value(session, "csrftoken")
    if csrf:
        extra_headers["X-CSRFToken"] = csrf
        actions.append("Attached Django CSRF token from cookie")


def _handle_flask(
    url: str,
    actions: list[str],
    extra_urls: list[str],
) -> None:
    probes = ["/api/", "/static/"]
    for p in probes:
        extra_urls.append(urljoin(url, p))
    actions.append(f"Probing Flask endpoints: {', '.join(probes)}")


def _handle_rails(
    url: str,
    session: "requests.Session",
    response: "requests.Response | None",
    actions: list[str],
    extra_urls: list[str],
    extra_headers: dict,
) -> None:
    probes = ["/rails/info/routes", "/api/"]
    for p in probes:
        extra_urls.append(urljoin(url, p))
    actions.append(
        f"Probing Rails endpoints (dev routes, API): {', '.join(probes)}"
    )

    # Authenticity token from response body
    body = _body(response)
    token = _extract_rails_token(body)
    if token:
        extra_headers["X-CSRF-Token"] = token
        actions.append("Extracted Rails authenticity_token for CSRF handling")


def _handle_laravel(
    url: str,
    session: "requests.Session",
    response: "requests.Response | None",
    actions: list[str],
    extra_urls: list[str],
    extra_headers: dict,
) -> None:
    probes = ["/api/", "/storage/"]
    for p in probes:
        extra_urls.append(urljoin(url, p))
    actions.append(f"Probing Laravel endpoints: {', '.join(probes)}")

    # XSRF-TOKEN from cookie (Laravel uses encrypted cookies)
    xsrf = _cookie_value(session, "XSRF-TOKEN")
    if xsrf:
        extra_headers["X-XSRF-TOKEN"] = xsrf
        actions.append("Attached Laravel XSRF-TOKEN from cookie")


def _handle_aspnet(
    url: str,
    response: "requests.Response | None",
    actions: list[str],
    extra_urls: list[str],
    extra_headers: dict,
) -> None:
    probes = ["/api/", "/_framework/"]
    for p in probes:
        extra_urls.append(urljoin(url, p))
    actions.append(f"Probing ASP.NET endpoints: {', '.join(probes)}")

    body = _body(response)
    viewstate = _extract_viewstate(body)
    if viewstate:
        extra_headers["X-ViewState-Available"] = "true"
        actions.append(
            "Detected __VIEWSTATE; form submissions will need it attached"
        )


# ------------------------------------------------------------------
# Utility helpers
# ------------------------------------------------------------------

_VIEWSTATE_RE = re.compile(
    r'name="__VIEWSTATE"\s+(?:id="[^"]*"\s+)?value="([^"]*)"',
    re.IGNORECASE,
)

_AUTH_TOKEN_RE = re.compile(
    r'name="authenticity_token"\s+value="([^"]*)"',
    re.IGNORECASE,
)


def _extract_viewstate(body: str) -> str | None:
    m = _VIEWSTATE_RE.search(body)
    return m.group(1) if m else None


def _extract_rails_token(body: str) -> str | None:
    m = _AUTH_TOKEN_RE.search(body)
    return m.group(1) if m else None


def _cookie_value(session: "requests.Session", name: str) -> str | None:
    try:
        return session.cookies.get(name)
    except Exception:
        return None


def _body(response: "requests.Response | None") -> str:
    if response is None:
        return ""
    try:
        return response.text or ""
    except Exception:
        return ""
