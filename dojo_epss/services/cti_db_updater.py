"""CTI DB sync service for package-owned CVE intelligence."""

from __future__ import annotations

import logging
from typing import Iterable

from django.db import connection, models
from django.utils import timezone

from ..models import (
    CTICVERecord,
    EPSSSettings,
    EPSSSource,
    EPSSUpdateLog,
)
from .csv_importer import download_and_parse
from .kev_source import fetch_matching_kev_rows
from .vulncheck_client import VulnCheckClient

log = logging.getLogger("dojo_epss.cti_db_updater")


# This function syncs global CVE intelligence. This function needs settings.
def sync_cti_db(
    settings: EPSSSettings | None = None,
    update_log: EPSSUpdateLog | None = None,
) -> dict:
    s = settings or EPSSSettings.load()
    stats = {
        "epss": {"seen": 0, "saved": 0, "skipped": False},
        "kev": {"seen": 0, "saved": 0, "matches": 0, "stale_cleared": 0, "skipped": False},
        "vulncheck": {
            "checked": 0,
            "records_seen": 0,
            "saved": 0,
            "matches": 0,
            "stale_cleared": 0,
            "requests_made": 0,
            "skipped": False,
            "skip_reason": "",
        },
        "total_seen": 0,
        "total_saved": 0,
        "total_matches": 0,
        "failed": 0,
    }

    if not s.cti_db_enabled:
        _update_log(update_log, stats, skipped_reason="cti_db_enabled=False")
        return stats

    if s.cti_db_sync_epss_enabled:
        final_date, rows, _batch = download_and_parse(settings=s, update_log=update_log, force=True)
        stats["epss"]["seen"] = len(rows)
        stats["epss"]["saved"] = _upsert_epss_rows(rows, source=EPSSSource.FIRST_CSV)
        stats["epss"]["score_date"] = final_date.isoformat()
    else:
        stats["epss"]["skipped"] = True

    if s.cti_db_sync_kev_enabled:
        result = fetch_matching_kev_rows(None, settings=s)
        stats["kev"]["seen"] = result.total_rows_seen
        stats["kev"]["matches"] = len(result.rows_by_cve)
        stats["kev"]["saved"] = _upsert_kev_rows(result.rows_by_cve.values(), s)
        stats["kev"]["stale_cleared"] = _clear_stale_kev_markers(result.rows_by_cve)
        stats["kev"]["source_type"] = result.source_type
        stats["kev"]["source_url"] = result.source_url
        stats["kev"]["catalog_version"] = result.catalog_version
        stats["kev"]["date_released"] = result.date_released
    else:
        stats["kev"]["skipped"] = True

    if s.cti_db_sync_vulncheck_enabled:
        token = s.get_vulncheck_api_token()
        if not token:
            stats["vulncheck"]["skipped"] = True
            stats["vulncheck"]["skip_reason"] = "VulnCheck API token is not configured"
        else:
            cves = CTICVERecord.objects.values_list("cve_id", flat=True).iterator(chunk_size=5000)
            result = VulnCheckClient(settings=s, token=token).fetch_cves(cves)
            stats["vulncheck"]["checked"] = result.cves_checked
            stats["vulncheck"]["records_seen"] = result.api_records_seen
            stats["vulncheck"]["matches"] = len(result.rows_by_cve)
            stats["vulncheck"]["requests_made"] = result.requests_made
            stats["vulncheck"]["saved"] = _upsert_vulncheck_rows(result.rows_by_cve.values())
            stats["vulncheck"]["stale_cleared"] = _clear_stale_vulncheck_markers(result.rows_by_cve)
            stats["vulncheck"]["source_index"] = result.source_index
            stats["vulncheck"]["available_indexes"] = result.available_indexes
    else:
        stats["vulncheck"]["skipped"] = True
        stats["vulncheck"]["skip_reason"] = "cti_db_sync_vulncheck_enabled=False"

    stats["total_seen"] = (
        stats["epss"]["seen"]
        + stats["kev"]["seen"]
        + stats["vulncheck"]["checked"]
    )
    stats["total_saved"] = (
        stats["epss"]["saved"]
        + stats["kev"]["saved"]
        + stats["vulncheck"]["saved"]
    )
    stats["total_matches"] = stats["kev"]["matches"] + stats["vulncheck"]["matches"]
    _update_log(update_log, stats)
    log.info("CTI DB sync complete stats=%s", stats)
    return stats


# This function saves EPSS rows to CTI DB. This function needs parsed CSV rows.
def _upsert_epss_rows(rows, source: str) -> int:
    if not rows:
        return 0
    now = timezone.now()
    objects = [
        CTICVERecord(
            cve_id=row.cve,
            epss_score=row.epss,
            epss_percentile=row.percentile,
            epss_date=row.score_date,
            epss_source=source,
            epss_raw_data=row.raw or {},
            last_seen_at=now,
            last_changed_at=now,
            updated_at=now,
        )
        for row in rows
    ]
    return _bulk_upsert(objects, [
        "epss_score",
        "epss_percentile",
        "epss_date",
        "epss_source",
        "epss_raw_data",
        "last_seen_at",
        "last_changed_at",
        "updated_at",
    ])


# This function saves KEV rows to CTI DB. This function needs KEV rows.
def _upsert_kev_rows(rows: Iterable, settings: EPSSSettings) -> int:
    row_list = list(rows)
    if not row_list:
        return 0
    now = timezone.now()
    today = timezone.localdate(now)
    existing = _existing_records([row.cve_id for row in row_list], [
        "cve_id",
        "kev_found_date",
        "ransomware_found_date",
    ])
    objects = []
    for row in row_list:
        old = existing.get(row.cve_id)
        objects.append(CTICVERecord(
            cve_id=row.cve_id,
            known_exploited=True,
            ransomware_used=row.ransomware_used,
            kev_date_added=row.date_added,
            kev_found_date=(old.kev_found_date if old else None) or today,
            ransomware_found_date=(
                ((old.ransomware_found_date if old else None) or today)
                if row.ransomware_used else (old.ransomware_found_date if old else None)
            ),
            kev_source_type=settings.kev_source_type,
            kev_source_url=settings.kev_source_url,
            kev_raw_data=row.raw_data or {},
            last_seen_at=now,
            last_changed_at=now,
            updated_at=now,
        ))
    return _bulk_upsert(objects, [
        "known_exploited",
        "ransomware_used",
        "kev_date_added",
        "kev_found_date",
        "ransomware_found_date",
        "kev_source_type",
        "kev_source_url",
        "kev_raw_data",
        "last_seen_at",
        "last_changed_at",
        "updated_at",
    ])


# This function saves VulnCheck rows to CTI DB. This function needs API rows.
def _upsert_vulncheck_rows(rows: Iterable) -> int:
    row_list = list(rows)
    if not row_list:
        return 0
    now = timezone.now()
    today = timezone.localdate(now)
    existing = _existing_records([row.cve_id for row in row_list], [
        "cve_id",
        "poc_found_date",
        "itw_found_date",
    ])
    objects = []
    for row in row_list:
        old = existing.get(row.cve_id)
        objects.append(CTICVERecord(
            cve_id=row.cve_id,
            public_exploit_found=row.public_exploit_found,
            exploit_in_the_wild=row.exploit_in_the_wild,
            commercial_exploit_found=row.commercial_exploit_found,
            weaponized_exploit_found=row.weaponized_exploit_found,
            reported_exploited_by_threat_actors=row.reported_exploited_by_threat_actors,
            reported_exploited_by_ransomware=row.reported_exploited_by_ransomware,
            reported_exploited_by_botnets=row.reported_exploited_by_botnets,
            reported_exploited_by_honeypot_service=row.reported_exploited_by_honeypot_service,
            reported_exploited_by_vulncheck_canaries=row.reported_exploited_by_vulncheck_canaries,
            in_cisa_kev=row.in_cisa_kev,
            in_vulncheck_kev=row.in_vulncheck_kev,
            max_exploit_maturity=row.max_exploit_maturity,
            poc_found_date=(
                ((old.poc_found_date if old else None) or row.poc_found_date or today)
                if row.public_exploit_found else (old.poc_found_date if old else None)
            ),
            itw_found_date=(
                ((old.itw_found_date if old else None) or row.itw_found_date or today)
                if row.exploit_in_the_wild else (old.itw_found_date if old else None)
            ),
            exploit_count=row.exploit_count,
            vulncheck_source_index=row.source_index,
            vulncheck_source_links=row.source_links,
            vulncheck_raw_data=row.raw_data or {},
            last_seen_at=now,
            last_changed_at=now,
            updated_at=now,
        ))
    return _bulk_upsert(objects, [
        "public_exploit_found",
        "exploit_in_the_wild",
        "commercial_exploit_found",
        "weaponized_exploit_found",
        "reported_exploited_by_threat_actors",
        "reported_exploited_by_ransomware",
        "reported_exploited_by_botnets",
        "reported_exploited_by_honeypot_service",
        "reported_exploited_by_vulncheck_canaries",
        "in_cisa_kev",
        "in_vulncheck_kev",
        "max_exploit_maturity",
        "poc_found_date",
        "itw_found_date",
        "exploit_count",
        "vulncheck_source_index",
        "vulncheck_source_links",
        "vulncheck_raw_data",
        "last_seen_at",
        "last_changed_at",
        "updated_at",
    ])


# This function clears stale KEV markers. This function needs current source rows.
def _clear_stale_kev_markers(rows_by_cve: dict) -> int:
    now = timezone.now()
    source_cves = set(rows_by_cve)
    qs = CTICVERecord.objects.filter(
        models.Q(known_exploited=True) | models.Q(ransomware_used=True),
    )
    if source_cves:
        qs = qs.exclude(cve_id__in=source_cves)
    return qs.update(
        known_exploited=False,
        ransomware_used=False,
        last_seen_at=now,
        last_changed_at=now,
        updated_at=now,
    )


# This function clears stale VulnCheck markers. This function needs current positive rows.
def _clear_stale_vulncheck_markers(rows_by_cve: dict) -> int:
    now = timezone.now()
    source_cves = set(rows_by_cve)
    qs = CTICVERecord.objects.filter(
        models.Q(public_exploit_found=True)
        | models.Q(exploit_in_the_wild=True)
        | models.Q(commercial_exploit_found=True)
        | models.Q(weaponized_exploit_found=True)
        | models.Q(reported_exploited_by_threat_actors=True)
        | models.Q(reported_exploited_by_ransomware=True)
        | models.Q(reported_exploited_by_botnets=True)
        | models.Q(reported_exploited_by_honeypot_service=True)
        | models.Q(reported_exploited_by_vulncheck_canaries=True)
        | models.Q(in_cisa_kev=True)
        | models.Q(in_vulncheck_kev=True)
    )
    if source_cves:
        qs = qs.exclude(cve_id__in=source_cves)
    return qs.update(
        public_exploit_found=False,
        exploit_in_the_wild=False,
        commercial_exploit_found=False,
        weaponized_exploit_found=False,
        reported_exploited_by_threat_actors=False,
        reported_exploited_by_ransomware=False,
        reported_exploited_by_botnets=False,
        reported_exploited_by_honeypot_service=False,
        reported_exploited_by_vulncheck_canaries=False,
        in_cisa_kev=False,
        in_vulncheck_kev=False,
        max_exploit_maturity="",
        exploit_count=0,
        vulncheck_source_links=[],
        last_seen_at=now,
        last_changed_at=now,
        updated_at=now,
    )


# This function loads existing records. This function needs CVE ids and fields.
def _existing_records(cves: list[str], fields: list[str]) -> dict[str, CTICVERecord]:
    out: dict[str, CTICVERecord] = {}
    for chunk in _chunks(sorted(set(cves)), 900):
        for row in CTICVERecord.objects.filter(cve_id__in=chunk).only(*fields):
            out[row.cve_id] = row
    return out


# This function bulk upserts CTI records. This function needs model objects.
def _bulk_upsert(objects: list[CTICVERecord], update_fields: list[str]) -> int:
    if not objects:
        return 0
    try:
        if connection.features.supports_update_conflicts:
            CTICVERecord.objects.bulk_create(
                objects,
                update_conflicts=True,
                update_fields=update_fields,
                unique_fields=["cve_id"],
                batch_size=2000,
            )
            return len(objects)
    except Exception as exc:  # pragma: no cover - feature-detect path
        log.warning("CTI DB bulk upsert failed (%s); falling back to per-row.", exc)

    written = 0
    for obj in objects:
        defaults = {
            field: getattr(obj, field)
            for field in update_fields
        }
        CTICVERecord.objects.update_or_create(cve_id=obj.cve_id, defaults=defaults)
        written += 1
    return written


# This function chunks values. This function needs a chunk size.
def _chunks(values: list[str], size: int):
    for start in range(0, len(values), size):
        yield values[start:start + size]


# This function updates a log row. This function needs CTI stats.
def _update_log(update_log: EPSSUpdateLog | None, stats: dict, skipped_reason: str = "") -> None:
    if update_log is None:
        return
    update_log.total_cves_fetched = stats["total_seen"]
    update_log.total_cves_saved = stats["total_saved"]
    update_log.total_matches = stats["total_matches"]
    update_log.total_failed = stats["failed"]
    update_log.details = {
        **(update_log.details or {}),
        "cti_db": {
            "epss": stats["epss"],
            "kev": stats["kev"],
            "vulncheck": stats["vulncheck"],
            "skipped_reason": skipped_reason,
        },
    }
    update_log.save(update_fields=[
        "total_cves_fetched",
        "total_cves_saved",
        "total_matches",
        "total_failed",
        "details",
    ])
