"""High-level EPSS row importer.

Wraps the lower-level fetch + upsert primitives in service-friendly entry
points the Celery tasks and management commands call directly.

Every public function returns a stats dict so the caller can write summary
counts to ``EPSSUpdateLog`` rows.

Primary entry point for normal operation: ``import_for_findings()``.
It walks DefectDojo Findings, extracts their CVE IDs, and queries
FIRST.org for **only those CVEs** — the right shape for a tool whose job
is "enrich my findings", not "mirror the whole EPSS catalog".
"""

from __future__ import annotations

import datetime as _dt
import logging
from typing import Iterable, Sequence

from .. import app_settings
from ..models import (
    EPSSCVERecord,
    EPSSSettings,
    EPSSSource,
    EPSSUpdateLog,
)
from ..queries import get_finding_model
from .csv_importer import download_and_parse, upsert_records
from .cve_extractor import extract_cves
from .first_client import EpssRow, FirstEPSSClient
from .http import EpssFetchError

log = logging.getLogger("dojo_epss.epss_importer")


# ---------------------------------------------------------------------------
# Finding-driven fetch (the primary use case)
# ---------------------------------------------------------------------------
# This function imports EPSS for Finding CVEs. This function needs DefectDojo Findings.
def import_for_findings(
    settings: EPSSSettings | None = None,
    finding_ids: Iterable[int] | None = None,
) -> tuple[list[EpssRow], int, int]:
    """Walk DefectDojo Findings, collect their CVE ids, and batch-query
    FIRST.org for exactly those CVEs.

    Returns ``(rows, written, cve_count)`` where:
      * rows       -- EpssRow objects returned by FIRST.org
      * written    -- count of EPSSCVERecord rows we upserted
      * cve_count  -- count of unique CVE ids we extracted from findings
                      (some may not exist in EPSS — those won't appear in rows)
    """
    s = settings or EPSSSettings.load()

    Finding = get_finding_model()
    qs = Finding.objects.all()
    if finding_ids is not None:
        qs = qs.filter(id__in=list(finding_ids))

    # Collect every distinct CVE id referenced by any Finding (legacy `cve`
    # field + Vulnerability_Id related rows + regex hits in text fields).
    seen: set[str] = set()
    for f in qs.iterator(chunk_size=500):
        for cve in extract_cves(f):
            seen.add(cve)

    cves = sorted(seen)
    log.info("import_for_findings: extracted %d unique CVE id(s) from %d Finding(s)",
             len(cves), qs.count())
    if not cves:
        return [], 0, 0

    client = FirstEPSSClient.from_settings(s)
    # client.fetch_batch already chunks at API_MAX_PAGE_SIZE.
    rows = client.fetch_batch(cves)
    written = upsert_records(rows, source=EPSSSource.FIRST_API)
    log.info("import_for_findings: FIRST.org returned EPSS data for %d / %d CVEs", len(rows), len(cves))
    return rows, written, len(cves)


# ---------------------------------------------------------------------------
# REST-API paths
# ---------------------------------------------------------------------------
# This function imports recent EPSS rows. This function needs FIRST.org settings.
def import_recent(
    settings: EPSSSettings | None = None,
    limit: int | None = None,
) -> tuple[list[EpssRow], int]:
    """Pull the most recent EPSS rows. Returns (rows, written)."""
    s = settings or EPSSSettings.load()
    if not s.fetch_recent_enabled:
        log.info("dojo_epss.import_recent: fetch_recent_enabled=False — skipping.")
        return [], 0
    client = FirstEPSSClient.from_settings(s)
    rows = client.fetch_recent(
        limit=limit or int(s.result_limit) or app_settings.API_MAX_PAGE_SIZE,
    )
    written = upsert_records(rows, source=EPSSSource.FIRST_API)
    return rows, written


# This function imports EPSS rows by threshold. This function needs threshold settings.
def import_by_threshold(
    settings: EPSSSettings | None = None,
) -> tuple[list[EpssRow], int]:
    s = settings or EPSSSettings.load()
    client = FirstEPSSClient.from_settings(s)
    rows = list(client.fetch_by_threshold(
        epss_gte=float(s.epss_score_threshold) if s.epss_score_threshold is not None else None,
        percentile_gte=float(s.epss_percentile_threshold) if s.epss_percentile_threshold is not None else None,
        date=s.fetch_date,
        order_by_epss_desc=s.order_by_epss_desc,
        limit=s.result_limit,
    ))
    written = upsert_records(rows, source=EPSSSource.FIRST_API)
    return rows, written


# This function imports one CVE. This function needs a CVE id.
def import_single(cve_id: str, settings: EPSSSettings | None = None) -> EpssRow | None:
    client = FirstEPSSClient.from_settings(settings)
    row = client.fetch_single(cve_id)
    if row is not None:
        upsert_records([row], source=EPSSSource.FIRST_API)
    return row


# This function imports a CVE batch. This function needs CVE ids.
def import_batch(cve_ids: Sequence[str], settings: EPSSSettings | None = None) -> tuple[list[EpssRow], int]:
    client = FirstEPSSClient.from_settings(settings)
    rows = client.fetch_batch(cve_ids)
    written = upsert_records(rows, source=EPSSSource.FIRST_API)
    return rows, written


# ---------------------------------------------------------------------------
# CSV path
# ---------------------------------------------------------------------------
# This function imports EPSS CSV data. This function needs CSV settings.
def import_csv(
    score_date: _dt.date | None = None,
    settings: EPSSSettings | None = None,
    update_log: EPSSUpdateLog | None = None,
) -> tuple[_dt.date, list[EpssRow], int]:
    s = settings or EPSSSettings.load()
    if not s.download_full_csv_enabled:
        log.info("dojo_epss.import_csv: download_full_csv_enabled=False — skipping.")
        return (score_date or _dt.date.today(), [], 0)
    final_date, rows, _batch = download_and_parse(score_date, s, update_log)
    written = upsert_records(rows, source=EPSSSource.FIRST_CSV)
    return final_date, rows, written
