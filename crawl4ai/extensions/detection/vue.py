"""
Vue.js detection.

Identifies Vue.js-powered websites by checking for ``data-v-``,
``__vue__``, ``Vue.config``, ``vue-router``, ``vuex``, and Vue library
script references in the response body.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["VueDetector"]


class VueDetector(BaseDetector):
    """Detect Vue.js-powered websites."""

    name = "vue"

    _SIGNATURES = (
        "data-v-",
        "__vue__",
        "vue.min.js",
        "vue.js",
        "data-vue-",
        "Vue.config",
        "vue-router",
        "vuex",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        if not body:
            return None
        for sig in self._SIGNATURES:
            if sig in body:
                return {"type": "vue", "method": "body", "signature": sig}
        return None
