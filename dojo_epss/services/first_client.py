"""FIRST.org EPSS REST client.

Implements every documented query pattern from the spec:

  * Most recent 100 CVEs ............ GET .../epss
  * Single CVE ...................... GET .../epss?cve=CVE-YYYY-NNNN
  * Batch CVEs ...................... GET .../epss?cve=A,B,C
  * CVEs above EPSS score (gt) ...... GET .../epss?epss-gt=0.95
  * CVEs above EPSS score (gte) ..... GET .../epss?epss-ge=0.95
  * CVEs above percentile ........... GET .../epss?percentile-gt=0.95
  * Sorted by highest EPSS .......... GET .../epss?order=!epss
  * Date-specific ................... GET .../epss?date=YYYY-MM-DD

Base URL is read from EPSSSettings.api_base_url (configurable; supports
internal mirrors / proxies). All HTTP calls go through ``request_with_retry``,
so connectivity issues never bubble up to a Django view.
"""

from __future__ import annotations

import datetime as _dt
import logging
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Iterable, Iterator, Sequence

from .. import app_settings
from ..models import EPSSSettings
from .http import EpssFetchError, build_session, request_with_retry

log = logging.getLogger("dojo_epss.first_client")


@dataclass(frozen=True)
class EpssRow:
    """One row of EPSS data returned from FIRST.org."""

    cve: str
    epss: Decimal
    percentile: Decimal
    score_date: _dt.date
    raw: dict

    # This function builds an EPSS row. This function needs API row data.
    @classmethod
    def from_api(cls, raw: dict) -> "EpssRow | None":
        try:
            cve = (raw["cve"] or "").strip().upper()
            if not cve:
                return None
            return cls(
                cve=cve,
                epss=Decimal(str(raw["epss"])),
                percentile=Decimal(str(raw["percentile"])),
                score_date=_dt.date.fromisoformat(raw["date"]),
                raw=raw,
            )
        except (InvalidOperation, KeyError, TypeError, ValueError) as exc:
            log.warning("dropping malformed EPSS row %r: %s", raw, exc)
            return None


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------
class FirstEPSSClient:
    """Thin wrapper around requests.Session.

    Use ``FirstEPSSClient.from_settings()`` from production code; the explicit
    constructor exists for tests / admin overrides.
    """

    def __init__(
        self,
        base_url: str = app_settings.DEFAULT_API_BASE_URL,
        timeout: int = app_settings.DEFAULT_HTTP_TIMEOUT_SECS,
        retries: int = app_settings.DEFAULT_HTTP_RETRIES,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = build_session(timeout=timeout)
        self.retries = retries
        self.timeout = timeout

    # This function builds a client from settings. This function needs EPSS settings.
    @classmethod
    def from_settings(cls, s: EPSSSettings | None = None) -> "FirstEPSSClient":
        s = s or EPSSSettings.load()
        return cls(
            base_url=s.api_base_url or app_settings.DEFAULT_API_BASE_URL,
            timeout=int(s.http_timeout_secs or app_settings.DEFAULT_HTTP_TIMEOUT_SECS),
            retries=int(s.http_retries or app_settings.DEFAULT_HTTP_RETRIES),
        )

    # --- low-level page fetch ------------------------------------------
    # This function fetches one API page. This function needs request params.
    def _get_page(self, params: dict) -> tuple[list[dict], int, int, int]:
        resp = request_with_retry(
            self.session, "GET", self.base_url,
            params=params, retries=self.retries, timeout=self.timeout,
        )
        try:
            payload = resp.json()
        except ValueError as exc:
            raise EpssFetchError(f"Non-JSON response from {self.base_url}: {exc}") from exc
        if not isinstance(payload, dict) or payload.get("status") not in ("OK", None):
            raise EpssFetchError(
                f"FIRST.org returned non-OK status: {payload.get('status')!r}",
            )
        data = payload.get("data") or []
        if not isinstance(data, list):
            raise EpssFetchError(f"Unexpected 'data' type: {type(data).__name__}")
        total = int(payload.get("total", len(data)))
        offset = int(payload.get("offset", 0))
        limit = int(payload.get("limit", len(data)))
        return data, total, offset, limit

    # --- public methods -------------------------------------------------
    # This function fetches recent EPSS rows. This function needs optional paging values.
    def fetch_recent(
        self,
        limit: int | None = None,
        offset: int = 0,
        order: str | None = None,
    ) -> list[EpssRow]:
        """Most-recent CVEs. ``limit`` capped at API_MAX_PAGE_SIZE per request."""
        params: dict = {}
        if limit:
            params["limit"] = min(limit, app_settings.API_MAX_PAGE_SIZE)
        if offset:
            params["offset"] = offset
        if order:
            params["order"] = order
        return _drop_none(EpssRow.from_api(r) for r in self._get_page(params)[0])

    # This function fetches one CVE. This function needs a CVE id.
    def fetch_single(self, cve_id: str) -> EpssRow | None:
        rows, *_ = self._get_page({"cve": cve_id.strip().upper()})
        for r in rows:
            row = EpssRow.from_api(r)
            if row is not None:
                return row
        return None

    # This function fetches many CVEs. This function needs CVE ids.
    def fetch_batch(self, cve_ids: Sequence[str]) -> list[EpssRow]:
        out: list[EpssRow] = []
        seen: set[str] = set()
        normalized: list[str] = []
        for c in cve_ids:
            cve = (c or "").strip().upper()
            if cve and cve not in seen:
                seen.add(cve)
                normalized.append(cve)
        chunk = max(1, app_settings.API_MAX_PAGE_SIZE)
        for i in range(0, len(normalized), chunk):
            page_cves = ",".join(normalized[i:i + chunk])
            rows, *_ = self._get_page({"cve": page_cves})
            out.extend(_drop_none(EpssRow.from_api(r) for r in rows))
        return out

    # This function fetches EPSS rows by filters. This function needs threshold values.
    def fetch_by_threshold(
        self,
        epss_gt: float | None = None,
        epss_gte: float | None = None,
        percentile_gt: float | None = None,
        percentile_gte: float | None = None,
        date: _dt.date | None = None,
        order_by_epss_desc: bool | None = None,
        limit: int | None = None,
    ) -> Iterator[EpssRow]:
        """Generator that paginates filtered results.

        Honors all the spec's query patterns:
          epss-gt, epss-ge, percentile-gt, percentile-ge, order=!epss, date.
        """
        base_params: dict = {}
        if epss_gt is not None:
            base_params["epss-gt"] = _fmt_pct(epss_gt)
        if epss_gte is not None:
            base_params["epss-ge"] = _fmt_pct(epss_gte)
        if percentile_gt is not None:
            base_params["percentile-gt"] = _fmt_pct(percentile_gt)
        if percentile_gte is not None:
            base_params["percentile-ge"] = _fmt_pct(percentile_gte)
        if date is not None:
            base_params["date"] = date.isoformat()
        if order_by_epss_desc:
            base_params["order"] = "!epss"

        page_size = app_settings.API_MAX_PAGE_SIZE
        offset = 0
        yielded = 0
        while True:
            params = dict(base_params, limit=page_size, offset=offset)
            data, total, _, _ = self._get_page(params)
            if not data:
                return
            for raw in data:
                row = EpssRow.from_api(raw)
                if row is None:
                    continue
                yield row
                yielded += 1
                if limit is not None and yielded >= limit:
                    return
            offset += len(data)
            if offset >= total:
                return

    # This function tests API connectivity. This function needs configured API settings.
    def test_connection(self) -> tuple[bool, str]:
        """Return (ok, message). Used by the /epss/manual/ "Test API" button."""
        try:
            rows = self.fetch_recent(limit=1)
            return True, f"OK — received {len(rows)} row(s)."
        except EpssFetchError as exc:
            return False, f"FIRST.org unreachable: {exc}"
        except Exception as exc:  # pylint: disable=broad-except
            return False, f"Unexpected error: {exc!s}"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
# This function removes empty rows. This function needs an iterable of rows.
def _drop_none(it: Iterable[EpssRow | None]) -> list[EpssRow]:
    return [x for x in it if x is not None]


# This function formats a percentage. This function needs a number.
def _fmt_pct(v) -> str:
    if v is None:
        return "0"
    f = float(v)
    f = max(0.0, min(1.0, f))
    return f"{f:.6f}".rstrip("0").rstrip(".") or "0"
