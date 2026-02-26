"""File saving and content hashing utilities."""

import hashlib
from pathlib import Path

from ..logging_setup import log


def save_file(local_path: Path, content: bytes) -> None:
    """Write *content* to *local_path*, creating all parent directories."""
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_bytes(content)
    log.debug("Saved → %s (%d bytes)", local_path, len(content))


def content_hash(data: bytes) -> str:
    """Return a short SHA-256 hex digest for deduplication."""
    return hashlib.sha256(data).hexdigest()[:16]
