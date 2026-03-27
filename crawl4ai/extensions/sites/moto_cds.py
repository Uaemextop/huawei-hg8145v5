"""
crawl4ai.extensions.sites.moto_cds – Site module for moto-cds.svcmot.cn.

Motorola Content Delivery System (CDS) hosts OTA firmware updates for
Motorola/Lenovo smartphones on a Google App Engine back-end behind nginx.

Infrastructure (observed via curl):
  - **nginx/1.14.1** reverse proxy in front of Google App Engine.
  - Landing page (``/``) is a minimal HTML page with a link to the
    ``/moto_cds`` servlet (currently 404).
  - The live API lives at ``/cds/upgrade/1/check/ctx/{context}/key/{guid}``
    where *context* is one of ``ota``, ``fota``, ``blur``, ``full``,
    ``recovery``, ``soak``, ``prerelease``, and *guid* is the device's
    ``ro.mot.build.guid`` SHA-1 hash.
  - Response header ``x-cds-content-exists: true|false`` indicates whether
    content is available before parsing the body.
  - Cache headers: ``Cache-Control: no-cache, no-store, must-revalidate``.

API request format (POST, JSON):
  ``User-Agent: com.motorola.ccc.ota``
  Body::

      {
        "id": "<serial_or_placeholder>",
        "deviceInfo": {"country": "<CC>", "region": "<CC>"},
        "extraInfo": {
          "carrier": "<carrier_code>",
          "vitalUpdate": false,
          "otaSourceSha1": "<guid>"
        },
        "triggeredBy": "user"
      }

API response when update available (``proceed: true``):
  ``content.version``         – firmware version string.
  ``content.otaSourceSha1``   – current build GUID.
  ``content.otaTargetSha1``   – next build GUID (for chaining).
  ``content.displayVersion``  – human-readable version.
  ``content.preInstallNotes`` – release notes.
  ``contentResources[].url``  – direct download URL for the OTA ZIP.
  ``contentResources[].hash`` – package hash.
  ``contentResources[].size`` – package size in bytes.

API response when no update (``proceed: false``):
  ``content: null``, ``contentResources: null``.

The ``moto-cds.appspot.com`` domain serves the same API on Google Front-End
(HTTP/2) without the nginx proxy.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.parse
from typing import TYPE_CHECKING, Any

from .base import BaseSiteModule, FileEntry

if TYPE_CHECKING:
    import requests

__all__ = ["MotoCDSModule"]

log = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────

_CDS_HOSTS = {"moto-cds.svcmot.cn", "moto-cds.appspot.com"}

_OTA_UA = "com.motorola.ccc.ota"

# API endpoint template.
_CHECK_PATH = "/cds/upgrade/1/check/ctx/{context}/key/{guid}"

# Contexts to probe for each device GUID.
_CONTEXTS = ("ota", "fota", "blur", "full")

# Delay between requests (seconds) to avoid rate-limiting.
_REQUEST_DELAY = 0.4

# Known Motorola device configurations used to probe the CDS API.
# Each entry contains the GUID (ro.mot.build.guid), carrier code,
# country/region, and descriptive label for logging.
# Real GUIDs must come from actual devices (build.prop).  The entries
# below are seed probes — they will yield ``proceed: false`` unless the
# server has a newer OTA for that exact build.
_DEVICE_CATALOG: list[dict[str, str]] = [
    {
        "guid": "14d0453e9070cca064b67d52dd620b7aa767fbdc",
        "carrier": "retcn",
        "country": "CN",
        "label": "Motorola CN retail seed",
    },
    {
        "guid": "af44c8c1-b7a0-4d52-a07a-3541f252ff3c",
        "carrier": "retus",
        "country": "US",
        "label": "Motorola US retail seed",
    },
    {
        "guid": "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0",
        "carrier": "retla",
        "country": "MX",
        "label": "Motorola LATAM retail seed",
    },
    {
        "guid": "c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9",
        "carrier": "reteu",
        "country": "DE",
        "label": "Motorola EU retail seed",
    },
    {
        "guid": "d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0",
        "carrier": "retbr",
        "country": "BR",
        "label": "Motorola Brazil retail seed",
    },
]

# Additional GUIDs can be loaded from the ``MOTO_CDS_GUIDS`` env variable
# (comma-separated SHA-1 hashes).  These are probed with default US/retail
# settings.


class MotoCDSModule(BaseSiteModule):
    """Site module for Motorola CDS firmware OTA API.

    Discovers OTA firmware packages by probing the CDS ``/cds/upgrade``
    API with known device GUIDs across multiple OTA contexts (ota, fota,
    blur, full).

    Custom GUIDs can be supplied via the ``MOTO_CDS_GUIDS`` environment
    variable (comma-separated SHA-1 hashes) to check specific builds.
    """

    name = "MotoCDSModule"
    hosts = list(_CDS_HOSTS)

    def matches(self, url: str) -> bool:
        """Return True if *url* points to a Motorola CDS host."""
        try:
            host = urllib.parse.urlparse(url).hostname or ""
        except Exception:
            return False
        return host.lower() in _CDS_HOSTS

    # ------------------------------------------------------------------
    # generate_index
    # ------------------------------------------------------------------

    def generate_index(self, url: str) -> list[FileEntry]:
        """Probe the Motorola CDS OTA API and return discovered files."""
        import os

        import requests as _requests

        sess = self.session or _requests.Session()
        entries: list[FileEntry] = []

        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.hostname}"

        log.info("[MotoCDS] Starting crawl of %s", base_url)

        # 1. Probe the landing page (/) to confirm reachability.
        self._probe_landing(sess, base_url)

        # 2. Build device list: built-in catalog + env overrides.
        devices = list(_DEVICE_CATALOG)
        env_guids = os.environ.get("MOTO_CDS_GUIDS", "").strip()
        if env_guids:
            for g in env_guids.split(","):
                g = g.strip()
                if g:
                    devices.append({
                        "guid": g,
                        "carrier": "retus",
                        "country": "US",
                        "label": f"env-GUID {g[:12]}…",
                    })
            log.info(
                "[MotoCDS] Added %d custom GUIDs from MOTO_CDS_GUIDS",
                len(devices) - len(_DEVICE_CATALOG),
            )

        # 3. Probe each device/context combination.
        checked = 0
        for device in devices:
            for context in _CONTEXTS:
                result = self._check_upgrade(
                    sess, base_url, device, context,
                )
                checked += 1
                if result:
                    entries.extend(result)
                time.sleep(_REQUEST_DELAY)

        log.info(
            "[MotoCDS] Crawl complete — %d probes, %d firmware entries found",
            checked,
            len(entries),
        )
        return entries

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _probe_landing(
        sess: "requests.Session", base_url: str,
    ) -> None:
        """GET the landing page and log basic info."""
        try:
            resp = sess.get(
                base_url, timeout=15,
                headers={"User-Agent": _OTA_UA},
            )
            log.info(
                "[MotoCDS] Landing page %s — HTTP %d, %d bytes, "
                "Server: %s, Content-Type: %s",
                base_url,
                resp.status_code,
                len(resp.content),
                resp.headers.get("Server", "?"),
                resp.headers.get("Content-Type", "?"),
            )
        except Exception as exc:
            log.warning("[MotoCDS] Landing page probe failed: %s", exc)

    @staticmethod
    def _check_upgrade(
        sess: "requests.Session",
        base_url: str,
        device: dict[str, str],
        context: str,
    ) -> list[FileEntry]:
        """POST to the OTA check endpoint and return FileEntry dicts
        for any firmware resources discovered."""
        guid = device["guid"]
        path = _CHECK_PATH.format(context=context, guid=guid)
        url = base_url + path

        payload: dict[str, Any] = {
            "id": "SERIAL_NOT_AVAILABLE",
            "deviceInfo": {
                "country": device.get("country", "US"),
                "region": device.get("country", "US"),
            },
            "extraInfo": {
                "carrier": device.get("carrier", "retus"),
                "vitalUpdate": False,
                "otaSourceSha1": guid,
            },
            "triggeredBy": "user",
        }

        headers = {
            "User-Agent": _OTA_UA,
            "Content-Type": "application/json",
        }

        try:
            resp = sess.post(url, json=payload, headers=headers, timeout=20)
        except Exception as exc:
            log.warning(
                "[MotoCDS] Request failed for %s ctx=%s: %s",
                device.get("label", guid[:12]),
                context,
                exc,
            )
            return []

        # Log the probe result.
        content_exists = resp.headers.get("x-cds-content-exists", "?")
        log.info(
            "[MotoCDS] %s ctx=%-5s HTTP %d x-cds-content-exists=%s",
            device.get("label", guid[:12]),
            context,
            resp.status_code,
            content_exists,
        )

        if resp.status_code != 200:
            return []

        try:
            data = resp.json()
        except (json.JSONDecodeError, ValueError):
            log.warning("[MotoCDS] Non-JSON response for %s", url)
            return []

        if not data.get("proceed"):
            return []

        # ── Parse positive response ──────────────────────────────────
        return MotoCDSModule._parse_ota_response(data, device, context, url)

    @staticmethod
    def _parse_ota_response(
        data: dict[str, Any],
        device: dict[str, str],
        context: str,
        source_url: str,
    ) -> list[FileEntry]:
        """Extract FileEntry dicts from a ``proceed: true`` response."""
        entries: list[FileEntry] = []
        content = data.get("content") or {}
        resources = data.get("contentResources") or []

        version = content.get("version", "unknown")
        display_version = content.get("displayVersion", version)
        source_sha1 = content.get("otaSourceSha1", "")
        target_sha1 = content.get("otaTargetSha1", "")
        notes = content.get("preInstallNotes", "")

        for res in resources:
            dl_url = (res.get("url") or "").strip()
            if not dl_url:
                continue

            size_bytes = res.get("size")
            size_str = ""
            if size_bytes and isinstance(size_bytes, (int, float)):
                if size_bytes >= 1_073_741_824:
                    size_str = f"{size_bytes / 1_073_741_824:.1f} GB"
                elif size_bytes >= 1_048_576:
                    size_str = f"{size_bytes / 1_048_576:.1f} MB"
                else:
                    size_str = f"{size_bytes / 1024:.0f} KB"

            entry: FileEntry = {
                "name": f"{version}.zip",
                "url": dl_url,
                "size": size_str,
                "version": display_version,
                "category": f"OTA firmware ({context})",
                "description": notes[:200] if notes else "",
                "source": f"CDS API ctx={context} guid={device.get('guid', '')[:16]}",
                "product": device.get("label", "Motorola"),
            }
            if res.get("hash"):
                entry["description"] = (
                    f"hash={res['hash']} " + entry.get("description", "")
                ).strip()

            entries.append(entry)
            log.info(
                "[MotoCDS] ✓ Found firmware: %s (%s) — %s",
                version,
                display_version,
                dl_url[:80],
            )

        if not entries and content:
            # Positive response but no downloadable resources — log it.
            log.info(
                "[MotoCDS] proceed=true but no contentResources for %s "
                "(version=%s, target=%s)",
                device.get("label", "?"),
                version,
                target_sha1[:16] if target_sha1 else "?",
            )

        return entries
