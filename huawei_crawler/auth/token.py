"""Anti-CSRF token retrieval for the Huawei HG8145V5 router."""

import requests

from ..config import RAND_COUNT_URL, REQUEST_TIMEOUT
from ..logging_setup import log
from ..session import base_url


def get_rand_token(session: requests.Session, host: str) -> str:
    """
    POST to /asp/GetRandCount.asp to obtain the one-time anti-CSRF token
    used as 'x.X_HW_Token' in the login form.
    """
    url = base_url(host) + RAND_COUNT_URL
    resp = session.post(url, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    token = resp.text.strip()
    log.debug("X_HW_Token: %s", token)
    return token
