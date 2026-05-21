"""Shared HTTP helpers.

Manual retry/backoff loop (instead of urllib3.Retry) avoids depending on a
specific urllib3 version — DefectDojo pins these centrally.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import requests

from .. import app_settings

log = logging.getLogger("dojo_epss.http")


class EpssFetchError(Exception):
    """Raised by service methods when an external call fails terminally."""


# This function builds an HTTP session. This function needs timeout and user agent values.
def build_session(timeout: int | None = None, user_agent: str | None = None) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": user_agent or app_settings.DEFAULT_USER_AGENT,
        "Accept": "application/json, text/csv;q=0.9, */*;q=0.5",
    })
    s.request_timeout = timeout or app_settings.DEFAULT_HTTP_TIMEOUT_SECS  # type: ignore[attr-defined]
    return s


# This function sends HTTP requests with retry. This function needs a session and URL.
def request_with_retry(
    session: requests.Session,
    method: str,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    stream: bool = False,
    retries: int | None = None,
    timeout: int | None = None,
    backoff: float | None = None,
) -> requests.Response:
    """GET/POST with bounded exponential backoff.

    Retries on connection errors and 5xx responses. 4xx responses are
    treated as client bugs and surfaced immediately.
    """
    retries = app_settings.DEFAULT_HTTP_RETRIES if retries is None else retries
    backoff = app_settings.DEFAULT_HTTP_BACKOFF if backoff is None else backoff
    timeout = (
        timeout
        or getattr(session, "request_timeout", app_settings.DEFAULT_HTTP_TIMEOUT_SECS)
    )

    attempt = 0
    last_exc: Exception | None = None
    while attempt <= retries:
        try:
            log.debug("HTTP %s %s params=%s attempt=%s", method, url, params, attempt)
            resp = session.request(method, url, params=params, timeout=timeout, stream=stream)
        except requests.RequestException as exc:
            last_exc = exc
        else:
            if 500 <= resp.status_code < 600:
                last_exc = EpssFetchError(f"{resp.status_code} from {url}")
            elif resp.status_code >= 400:
                raise EpssFetchError(
                    f"{resp.status_code} from {url}: {resp.text[:300]}",
                )
            else:
                return resp

        wait = backoff * (2 ** attempt)
        log.warning(
            "EPSS HTTP attempt %s/%s failed for %s: %s (sleep %.1fs)",
            attempt + 1, retries + 1, url, last_exc, wait,
        )
        if attempt < retries:
            time.sleep(wait)
        attempt += 1

    raise EpssFetchError(
        f"All {retries + 1} attempts failed for {url}: {last_exc}",
    )
