"""
Huawei HG8145V5 Router Web Crawler – modular package.
"""

__version__ = "1.0.0"

from .config import DEFAULT_HOST, DEFAULT_USER, DEFAULT_PASSWORD, DEFAULT_OUTPUT
from .session import build_session, base_url
from .auth import login, detect_login_mode, is_session_expired
from .extraction import extract_links
from .crawler import Crawler
from .cli import main

__all__ = [
    "DEFAULT_HOST",
    "DEFAULT_USER",
    "DEFAULT_PASSWORD",
    "DEFAULT_OUTPUT",
    "build_session",
    "base_url",
    "login",
    "detect_login_mode",
    "is_session_expired",
    "extract_links",
    "Crawler",
    "main",
]
