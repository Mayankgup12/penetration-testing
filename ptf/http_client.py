"""HTTP helpers with retries and rate limiting."""

from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


def build_session(cfg: dict[str, Any]) -> requests.Session:
    http = cfg.get("http", {})
    timeout = float(http.get("timeout_seconds", 15))
    retries = int(http.get("max_retries", 3))
    backoff = float(http.get("retry_backoff_seconds", 1.5))
    ua = http.get("user_agent", "PTF/1.0")

    session = requests.Session()
    session.headers.update({"User-Agent": ua, "Accept": "text/html,application/xhtml+xml,*/*"})

    retry = Retry(
        total=retries,
        connect=retries,
        read=retries,
        status=retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "HEAD", "POST"]),
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    session._ptf_timeout = timeout  # type: ignore[attr-defined]
    session._ptf_rate = float(http.get("rate_limit_seconds", 0.35))  # type: ignore[attr-defined]
    session._ptf_last_request = 0.0  # type: ignore[attr-defined]
    return session


def rate_limit_sleep(session: requests.Session) -> None:
    gap = getattr(session, "_ptf_rate", 0.35)
    last = getattr(session, "_ptf_last_request", 0.0)
    now = time.monotonic()
    wait = last + gap - now
    if wait > 0:
        time.sleep(wait)
    setattr(session, "_ptf_last_request", time.monotonic())


def get_timeout(session: requests.Session) -> float:
    return float(getattr(session, "_ptf_timeout", 15))


def safe_get(session: requests.Session, url: str, **kwargs: Any) -> requests.Response:
    rate_limit_sleep(session)
    timeout = kwargs.pop("timeout", get_timeout(session))
    return session.get(url, timeout=timeout, allow_redirects=True, **kwargs)


def safe_post(session: requests.Session, url: str, **kwargs: Any) -> requests.Response:
    rate_limit_sleep(session)
    timeout = kwargs.pop("timeout", get_timeout(session))
    return session.post(url, timeout=timeout, allow_redirects=True, **kwargs)


def normalize_target_url(url: str) -> str:
    u = url.strip()
    if not u:
        raise ValueError("Empty URL")
    parsed = urlparse(u)
    if not parsed.scheme:
        u = "http://" + u
        parsed = urlparse(u)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http and https URLs are allowed")
    if not parsed.netloc:
        raise ValueError("Invalid URL: missing host")
    return u


def same_registrable_domain(base: str, other: str) -> bool:
    try:
        b = urlparse(base).netloc.lower()
        o = urlparse(other).netloc.lower()
        if not b or not o:
            return False
        if b == o:
            return True
        if b.startswith("www.") and o == b[4:]:
            return True
        if o.startswith("www.") and b == o[4:]:
            return True
    except Exception:
        logger.debug("same_registrable_domain compare failed", exc_info=True)
    return False
