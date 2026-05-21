"""KEV feed fetch/parsing helpers.

The public CISA KEV source is a full JSON/CSV feed, not a per-CVE lookup API.
We still treat it as transient input: parse it in memory, keep only CVEs that
exist in DefectDojo Findings, and never persist the full feed.
"""

from __future__ import annotations

import csv
import datetime as _dt
import gzip
import io
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Iterable

from ..models import EPSSSettings, KEVSourceType
from .cve_extractor import CVE_RE
from .http import EpssFetchError, build_session, request_with_retry

log = logging.getLogger("dojo_epss.kev_source")


@dataclass(frozen=True)
class KevRow:
    cve_id: str
    ransomware_used: bool
    date_added: _dt.date | None
    raw_data: dict[str, Any]


@dataclass(frozen=True)
class KevFetchResult:
    rows_by_cve: dict[str, KevRow]
    total_rows_seen: int
    catalog_version: str
    date_released: str
    source_url: str
    source_type: str


# This function fetches matching KEV rows. This function needs target CVEs.
def fetch_matching_kev_rows(
    cves: Iterable[str],
    settings: EPSSSettings | None = None,
) -> KevFetchResult:
    """Fetch configured KEV source and return only rows matching ``cves``."""
    s = settings or EPSSSettings.load()
    target_cves = {_normalize_cve(c) for c in cves if _normalize_cve(c)}
    source_url = (s.kev_source_url or "").strip()
    source_type = s.kev_source_type or KEVSourceType.JSON

    if not source_url:
        raise EpssFetchError("KEV source URL is empty.")
    if not target_cves:
        return KevFetchResult({}, 0, "", "", source_url, source_type)

    sess = build_session(timeout=int(s.http_timeout_secs))
    resp = request_with_retry(
        sess,
        "GET",
        source_url,
        retries=int(s.http_retries),
        timeout=int(s.http_timeout_secs),
    )

    if source_type == KEVSourceType.CSV:
        rows, total = _parse_csv_response(resp.content, source_url, target_cves)
        catalog_version = ""
        date_released = ""
    else:
        rows, total, catalog_version, date_released = _parse_json_response(
            resp.content,
            source_url,
            target_cves,
        )

    rows_by_cve: dict[str, KevRow] = {}
    for row in rows:
        prev = rows_by_cve.get(row.cve_id)
        if prev is None or (row.ransomware_used and not prev.ransomware_used):
            rows_by_cve[row.cve_id] = row

    log.info(
        "KEV source parsed source_type=%s rows=%d matched_cves=%d",
        source_type,
        total,
        len(rows_by_cve),
    )
    return KevFetchResult(
        rows_by_cve=rows_by_cve,
        total_rows_seen=total,
        catalog_version=catalog_version,
        date_released=date_released,
        source_url=source_url,
        source_type=source_type,
    )


# This function parses KEV JSON. This function needs response bytes and target CVEs.
def _parse_json_response(
    content: bytes,
    source_url: str,
    target_cves: set[str],
) -> tuple[list[KevRow], int, str, str]:
    try:
        data = json.loads(_decode_content(content, source_url))
    except json.JSONDecodeError as exc:
        raise EpssFetchError(f"KEV JSON parse failed: {exc}") from exc

    catalog_version = ""
    date_released = ""
    if isinstance(data, dict):
        catalog_version = str(data.get("catalogVersion") or data.get("catalog_version") or "")
        date_released = str(data.get("dateReleased") or data.get("date_released") or "")
        items = data.get("vulnerabilities") or data.get("data") or data.get("results")
    elif isinstance(data, list):
        items = data
    else:
        items = None

    if not isinstance(items, list):
        raise EpssFetchError(
            "KEV JSON source must be a list or an object with a vulnerabilities/data/results list.",
        )

    rows: list[KevRow] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        row = _row_from_mapping(item)
        if row and row.cve_id in target_cves:
            rows.append(row)
    return rows, len(items), catalog_version, date_released


# This function parses KEV CSV. This function needs response bytes and target CVEs.
def _parse_csv_response(
    content: bytes,
    source_url: str,
    target_cves: set[str],
) -> tuple[list[KevRow], int]:
    text = _decode_content(content, source_url)
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise EpssFetchError("KEV CSV source has no header row.")

    rows: list[KevRow] = []
    total = 0
    for raw in reader:
        total += 1
        row = _row_from_mapping(raw)
        if row and row.cve_id in target_cves:
            rows.append(row)
    return rows, total


# This function builds a KEV row. This function needs one feed row.
def _row_from_mapping(raw: dict[str, Any]) -> KevRow | None:
    norm = {_normalize_key(k): v for k, v in raw.items()}
    cve_id = _normalize_cve(_first(norm, "cveid", "cve", "cveidnumber"))
    if not cve_id:
        return None

    ransomware = _truthy_ransomware(_first(
        norm,
        "knownransomwarecampaignuse",
        "knowntobeusedinransomwarecampaigns",
        "usedinransomware",
        "ransomwareused",
        "ransomware",
    ))
    date_added = _parse_date(_first(norm, "dateadded", "kevdate", "date"))

    return KevRow(
        cve_id=cve_id,
        ransomware_used=ransomware,
        date_added=date_added,
        raw_data=dict(raw),
    )


# This function decodes feed content. This function needs response bytes and source URL.
def _decode_content(content: bytes, source_url: str) -> str:
    try:
        if content[:2] == b"\x1f\x8b" or source_url.lower().endswith(".gz"):
            content = gzip.decompress(content)
    except OSError as exc:
        raise EpssFetchError(f"KEV gzip decode failed: {exc}") from exc
    return content.decode("utf-8-sig")


# This function normalizes a key. This function needs a raw key.
def _normalize_key(key: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key or "").lower())


# This function returns the first present value. This function needs normalized data.
def _first(norm: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = norm.get(key)
        if value not in (None, ""):
            return value
    return None


# This function normalizes a CVE value. This function needs raw text.
def _normalize_cve(value: Any) -> str:
    if not value:
        return ""
    match = CVE_RE.search(str(value))
    if not match:
        return ""
    return f"CVE-{match.group(1)}-{match.group(2)}".upper()


# This function reads ransomware truth. This function needs a feed value.
def _truthy_ransomware(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    return text in {"known", "yes", "true", "1", "y", "used"}


# This function parses a date. This function needs a feed value.
def _parse_date(value: Any) -> _dt.date | None:
    if isinstance(value, _dt.date):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return _dt.date.fromisoformat(text[:10])
    except ValueError:
        return None
