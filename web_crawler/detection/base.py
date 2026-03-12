"""Base class for all page technology detectors."""

from abc import ABC, abstractmethod


class BaseDetector(ABC):
    """Detects a specific technology or protection on a web page.

    Subclasses implement :meth:`detect` which inspects the HTTP response
    (status code, headers, body) and returns a detection dict when the
    technology is found, or ``None`` otherwise.
    """

    name: str = ""

    @abstractmethod
    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        """Check whether this technology is present.

        Returns
        -------
        dict | None
            A dict with at least ``{"type": "<name>", ...}`` on detection,
            or ``None`` when not detected.
        """
        ...
