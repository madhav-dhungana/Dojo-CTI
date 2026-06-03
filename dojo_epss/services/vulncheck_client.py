"""VulnCheck API client for POC / ITW signals."""

from __future__ import annotations

import datetime as _dt
import logging
import re
from dataclasses import dataclass
from typing import Any, Iterable

from .. import app_settings
from ..models import EPSSSettings
from .cve_extractor import CVE_RE
from .http import EpssFetchError, build_session, request_with_retry

log = logging.getLogger("dojo_epss.vulncheck_client")


@dataclass(frozen=True)
class VulnCheckRow:
    cve_id: str
    public_exploit_found: bool
    exploit_in_the_wild: bool
    commercial_exploit_found: bool
    weaponized_exploit_found: bool
    reported_exploited_by_threat_actors: bool
    reported_exploited_by_ransomware: bool
    reported_exploited_by_botnets: bool
    reported_exploited_by_honeypot_service: bool
    reported_exploited_by_vulncheck_canaries: bool
    in_cisa_kev: bool
    in_vulncheck_kev: bool
    max_exploit_maturity: str
    poc_found_date: _dt.date | None
    itw_found_date: _dt.date | None
    exploit_count: int
    source_index: str
    source_links: list[dict[str, Any]]
    raw_data: dict[str, Any]


@dataclass(frozen=True)
class VulnCheckFetchResult:
    rows_by_cve: dict[str, VulnCheckRow]
    cves_checked: int
    api_records_seen: int
    requests_made: int
    source_index: str
    available_indexes: list[str]


class VulnCheckClient:
    """Small client for VulnCheck v3 index queries."""

    def __init__(self, settings: EPSSSettings, token: str):
        self.settings = settings
        self.base_url = (
            settings.vulncheck_api_base_url
            or app_settings.DEFAULT_VULNCHECK_API_BASE_URL
        ).rstrip("/")
        self.index = (settings.vulncheck_index or app_settings.DEFAULT_VULNCHECK_INDEX).strip()
        self.session = build_session(timeout=int(settings.http_timeout_secs))
        self.session.headers.update({
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        })

    # This function lists accessible indexes. This function needs a valid token.
    def list_indexes(self) -> list[str]:
        url = f"{self.base_url}/index"
        try:
            resp = request_with_retry(
                self.session,
                "GET",
                url,
                retries=int(self.settings.http_retries),
                timeout=int(self.settings.http_timeout_secs),
            )
            data = resp.json()
        except Exception as exc:
            raise EpssFetchError(_sanitize_error(f"VulnCheck index list failed: {exc!s}")) from exc

        items = data.get("data") if isinstance(data, dict) else []
        names = []
        for item in items or []:
            if isinstance(item, str):
                names.append(item)
            elif isinstance(item, dict):
                name = item.get("name") or item.get("index") or item.get("_id") or item.get("id")
                if name:
                    names.append(str(name))
        return sorted(set(names))

    # This function fetches POC and ITW rows. This function needs CVE ids.
    def fetch_cves(self, cves: Iterable[str]) -> VulnCheckFetchResult:
        target_cves = sorted({_normalize_cve(cve) for cve in cves if _normalize_cve(cve)})
        available_indexes = self.list_indexes()
        if self.index not in available_indexes:
            raise EpssFetchError(
                _sanitize_error(
                    f"VulnCheck token cannot access index {self.index!r}. "
                    "Check the token license or choose an accessible index.",
                ),
            )

        rows_by_cve: dict[str, VulnCheckRow] = {}
        api_records_seen = 0
        requests_made = 0
        for chunk in _chunks(target_cves, app_settings.VULNCHECK_MAX_CVES_PER_REQUEST):
            chunk_rows, chunk_seen, chunk_requests = self._fetch_chunk(chunk)
            api_records_seen += chunk_seen
            requests_made += chunk_requests
            for row in chunk_rows:
                if row.public_exploit_found or row.exploit_in_the_wild:
                    rows_by_cve[row.cve_id] = row

        log.info(
            "VulnCheck fetched checked=%d records=%d matched=%d requests=%d",
            len(target_cves),
            api_records_seen,
            len(rows_by_cve),
            requests_made,
        )
        return VulnCheckFetchResult(
            rows_by_cve=rows_by_cve,
            cves_checked=len(target_cves),
            api_records_seen=api_records_seen,
            requests_made=requests_made,
            source_index=self.index,
            available_indexes=available_indexes,
        )

    # This function fetches one CVE chunk. This function needs at most 1000 CVEs.
    def _fetch_chunk(self, cves: list[str]) -> tuple[list[VulnCheckRow], int, int]:
        url = f"{self.base_url}/index/{self.index}"
        body: dict[str, Any] = {
            "cves": cves,
            "limit": min(len(cves), app_settings.VULNCHECK_DEFAULT_LIMIT),
        }
        rows: list[VulnCheckRow] = []
        total_seen = 0
        requests_made = 0
        cursor = ""

        while True:
            payload = {**body}
            if cursor:
                payload["cursor"] = cursor
            try:
                resp = request_with_retry(
                    self.session,
                    "POST",
                    url,
                    json=payload,
                    retries=int(self.settings.http_retries),
                    timeout=int(self.settings.http_timeout_secs),
                )
                data = resp.json()
            except Exception as exc:
                raise EpssFetchError(_sanitize_error(f"VulnCheck query failed: {exc!s}")) from exc

            requests_made += 1
            records = data.get("data") if isinstance(data, dict) else []
            for record in records or []:
                if not isinstance(record, dict):
                    continue
                total_seen += 1
                row = _row_from_record(record, self.index)
                if row is not None:
                    rows.append(row)

            meta = {}
            if isinstance(data, dict):
                meta = data.get("_meta") or data.get("meta") or {}
            next_cursor = str((meta or {}).get("next_cursor") or "")
            if not next_cursor:
                break
            cursor = next_cursor

        return rows, total_seen, requests_made


# This function builds a row from VulnCheck data. This function needs one record.
def _row_from_record(record: dict[str, Any], index: str) -> VulnCheckRow | None:
    cve_id = _normalize_cve(record.get("id") or record.get("cve") or record.get("cve_id"))
    if not cve_id:
        return None

    max_maturity = str(record.get("max_exploit_maturity") or "").strip()
    exploit_links = _source_links(record.get("exploits"), limit=20)
    exploitation_links = _source_links(record.get("reported_exploitation"), limit=20)
    public_exploit_found = bool(record.get("public_exploit_found")) or any(
        _truthy_public_exploit(link) for link in exploit_links
    )
    weaponized = bool(record.get("weaponized_exploit_found"))
    itw = any(bool(record.get(name)) for name in (
        "reported_exploited",
        "reported_exploited_by_threat_actors",
        "reported_exploited_by_ransomware",
        "reported_exploited_by_botnets",
        "reported_exploited_by_honeypot_service",
        "reported_exploited_by_vulncheck_canaries",
        "inKEV",
        "inVCKEV",
    ))

    timeline = record.get("timeline") if isinstance(record.get("timeline"), dict) else {}
    poc_date = _first_date([
        timeline.get("first_exploit_published"),
        record.get("date_added"),
        *[link.get("date_added") for link in exploit_links],
    ])
    itw_date = _first_date([
        timeline.get("vulncheck_kev_date_added"),
        timeline.get("cisa_kev_date_added"),
        timeline.get("first_reported_threat_actor"),
        timeline.get("first_reported_ransomware"),
        timeline.get("first_reported_botnet"),
        timeline.get("first_exploit_published_weaponized_or_higher") if itw else None,
        *[link.get("date_added") for link in exploitation_links],
    ])

    counts = record.get("counts") if isinstance(record.get("counts"), dict) else {}
    source_links = [*exploit_links, *exploitation_links][:25]
    raw_data = {
        "id": cve_id,
        "public_exploit_found": public_exploit_found,
        "commercial_exploit_found": bool(record.get("commercial_exploit_found")),
        "weaponized_exploit_found": weaponized,
        "reported_exploited": bool(record.get("reported_exploited")),
        "reported_exploited_by_threat_actors": bool(record.get("reported_exploited_by_threat_actors")),
        "reported_exploited_by_ransomware": bool(record.get("reported_exploited_by_ransomware")),
        "reported_exploited_by_botnets": bool(record.get("reported_exploited_by_botnets")),
        "reported_exploited_by_honeypot_service": bool(record.get("reported_exploited_by_honeypot_service")),
        "reported_exploited_by_vulncheck_canaries": bool(record.get("reported_exploited_by_vulncheck_canaries")),
        "inKEV": bool(record.get("inKEV")),
        "inVCKEV": bool(record.get("inVCKEV")),
        "max_exploit_maturity": max_maturity,
        "timeline": timeline,
        "counts": counts,
        "source_links": source_links,
    }

    return VulnCheckRow(
        cve_id=cve_id,
        public_exploit_found=public_exploit_found,
        exploit_in_the_wild=itw,
        commercial_exploit_found=bool(record.get("commercial_exploit_found")),
        weaponized_exploit_found=weaponized,
        reported_exploited_by_threat_actors=bool(record.get("reported_exploited_by_threat_actors")),
        reported_exploited_by_ransomware=bool(record.get("reported_exploited_by_ransomware")),
        reported_exploited_by_botnets=bool(record.get("reported_exploited_by_botnets")),
        reported_exploited_by_honeypot_service=bool(record.get("reported_exploited_by_honeypot_service")),
        reported_exploited_by_vulncheck_canaries=bool(record.get("reported_exploited_by_vulncheck_canaries")),
        in_cisa_kev=bool(record.get("inKEV")),
        in_vulncheck_kev=bool(record.get("inVCKEV")),
        max_exploit_maturity=max_maturity,
        poc_found_date=poc_date,
        itw_found_date=itw_date,
        exploit_count=_safe_int(counts.get("exploits")),
        source_index=index,
        source_links=source_links,
        raw_data=raw_data,
    )


# This function normalizes a CVE value. This function needs raw text.
def _normalize_cve(value: Any) -> str:
    if not value:
        return ""
    match = CVE_RE.search(str(value))
    if not match:
        return ""
    return f"CVE-{match.group(1)}-{match.group(2)}".upper()


# This function chunks values. This function needs a chunk size.
def _chunks(values: list[str], size: int):
    for start in range(0, len(values), size):
        yield values[start:start + size]


# This function extracts useful links. This function needs a VulnCheck list.
def _source_links(value: Any, limit: int = 20) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    out: list[dict[str, Any]] = []
    for item in value[:limit]:
        if not isinstance(item, dict):
            continue
        clean = {
            key: item.get(key)
            for key in (
                "url",
                "reference_url",
                "name",
                "refsource",
                "date_added",
                "exploit_maturity",
                "exploit_availability",
                "exploit_type",
            )
            if item.get(key) not in (None, "")
        }
        if clean:
            out.append(clean)
    return out


# This function checks public exploit links. This function needs one link.
def _truthy_public_exploit(link: dict[str, Any]) -> bool:
    text = " ".join(str(link.get(key) or "").lower() for key in (
        "exploit_availability",
        "exploit_maturity",
        "refsource",
    ))
    return "public" in text or "poc" in text


# This function returns the earliest date. This function needs date-like values.
def _first_date(values: Iterable[Any]) -> _dt.date | None:
    parsed = [_parse_date(value) for value in values if value]
    parsed = [value for value in parsed if value is not None]
    return min(parsed) if parsed else None


# This function parses VulnCheck dates. This function needs a raw value.
def _parse_date(value: Any) -> _dt.date | None:
    if isinstance(value, _dt.datetime):
        return value.date()
    if isinstance(value, _dt.date):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return _dt.datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return _dt.date.fromisoformat(text[:10])
        except ValueError:
            return None


# This function converts numbers safely. This function needs any value.
def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


# This function removes secrets from error text. This function needs an error.
def _sanitize_error(message: str) -> str:
    message = re.sub(r"Bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [redacted]", message)
    return message[:8000]
