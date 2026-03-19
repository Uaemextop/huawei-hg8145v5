"""
Joomla CMS detection.

Identifies Joomla-powered websites by checking the ``generator`` and
``x-powered-by`` headers for Joomla references, as well as body signatures
such as ``/media/jui/``, ``/components/com_``, and ``Joomla!``.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["JoomlaDetector"]


class JoomlaDetector(BaseDetector):
    """Detect Joomla-powered websites."""

    name = "joomla"

    _SIGNATURES = (
        "/media/jui/",
        "/components/com_",
        'content="Joomla',
        "/administrator/",
        "Joomla!",
        "/media/system/js/",
        "joomla.javascript.js",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        # Check headers
        generator = headers.get("generator", headers.get("x-generator", ""))
        if "joomla" in generator.lower():
            return {"type": "joomla", "method": "header",
                    "signature": "generator"}

        powered_by = headers.get("x-powered-by", "")
        if "joomla" in powered_by.lower():
            return {"type": "joomla", "method": "header",
                    "signature": "x-powered-by"}

        # Check body signatures
        if body:
            for sig in self._SIGNATURES:
                if sig in body:
                    return {"type": "joomla", "method": "body",
                            "signature": sig}

        return None
