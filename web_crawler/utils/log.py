"""Coloured logging setup with GitHub Actions support.

Delegates to :mod:`crawl4ai.extensions.log_utils`.
"""

from crawl4ai.extensions.log_utils import (  # noqa: F401
    log,
    setup_logging,
    ci_group,
    ci_endgroup,
)

__all__ = ["log", "setup_logging", "ci_group", "ci_endgroup"]
