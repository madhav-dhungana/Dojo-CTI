"""KEV matcher/updater.

Positive-only semantics:
  * A matching CVE can set Finding.known_exploited=True.
  * A matching ransomware signal can set Finding.ransomware_used=True.
  * Finding.kev_date is set once to the local first-found date.
  * Later scans never reset those Finding fields or overwrite found dates.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Iterable

from django.db import transaction
from django.utils import timezone

from ..models import (
    EPSSSettings,
    EPSSStatus,
    EPSSUpdateLog,
    FindingKEVUpdate,
)
from ..queries import get_finding_model
from .cve_extractor import extract_cves_with_origins
from .kev_source import KevRow, fetch_matching_kev_rows

log = logging.getLogger("dojo_epss.kev_updater")


# This function syncs KEV data to Findings. This function needs KEV settings.
def sync_kev_findings(
    settings: EPSSSettings | None = None,
    update_log: EPSSUpdateLog | None = None,
) -> dict:
    """Fetch configured KEV source and positively update matching Findings."""
    s = settings or EPSSSettings.load()
    stats = {
        "scanned": 0,
        "with_cves": 0,
        "source_rows_seen": 0,
        "matched_cves": 0,
        "matched_findings": 0,
        "updated_findings": 0,
        "skipped": 0,
        "failed": 0,
        "details": {},
    }

    if not s.kev_update_findings_enabled:
        stats["details"]["skipped_reason"] = "kev_update_findings_enabled=False"
        _update_log(update_log, stats, s)
        return stats

    finding_items, all_cves = _collect_finding_cves()
    stats["scanned"] = finding_items["scanned_count"]
    stats["with_cves"] = len(finding_items["with_cves"])

    if not all_cves:
        stats["details"]["skipped_reason"] = "no CVEs found in Findings"
        _update_log(update_log, stats, s)
        return stats

    fetch_result = fetch_matching_kev_rows(all_cves, settings=s)
    stats["source_rows_seen"] = fetch_result.total_rows_seen
    stats["matched_cves"] = len(fetch_result.rows_by_cve)
    stats["details"] = {
        "source_type": fetch_result.source_type,
        "source_url": fetch_result.source_url,
        "catalog_version": fetch_result.catalog_version,
        "date_released": fetch_result.date_released,
        "unique_finding_cves": len(all_cves),
        "matched_cves_sample": sorted(fetch_result.rows_by_cve)[:100],
    }

    first_dates = _existing_first_dates(fetch_result.rows_by_cve.keys())
    pgh = _import_pghistory()

    with _audit_context(pgh):
        for finding, cves in finding_items["with_cves"]:
            try:
                changed = _update_one_finding(
                    finding=finding,
                    cves=cves,
                    rows_by_cve=fetch_result.rows_by_cve,
                    first_dates=first_dates,
                    settings=s,
                )
            except Exception as exc:  # pylint: disable=broad-except
                log.exception("KEV update failed for finding=%s", getattr(finding, "id", None))
                _mark_failed(finding, cves, s, exc)
                stats["failed"] += 1
                continue

            if changed["matched"]:
                stats["matched_findings"] += 1
                if changed["updated"]:
                    stats["updated_findings"] += 1
            else:
                stats["skipped"] += 1

    _update_log(update_log, stats, s)
    log.info(
        "sync_kev_findings(): scanned=%d with_cves=%d matched_findings=%d updated=%d skipped=%d failed=%d",
        stats["scanned"],
        stats["with_cves"],
        stats["matched_findings"],
        stats["updated_findings"],
        stats["skipped"],
        stats["failed"],
    )
    return stats


# This function collects Finding CVEs. This function needs the Finding model.
def _collect_finding_cves() -> tuple[dict, set[str]]:
    Finding = get_finding_model()
    fields_we_use = _safe_field_names([
        "id",
        "cve",
        "title",
        "description",
        "references",
        "mitigation",
        "impact",
        "steps_to_reproduce",
        "component_name",
        "component_version",
        "known_exploited",
        "ransomware_used",
        "kev_date",
    ])
    qs = Finding.objects.all()
    if fields_we_use:
        qs = qs.only(*fields_we_use)
    prefetches = _safe_prefetch_names()
    if prefetches:
        qs = qs.prefetch_related(*prefetches)

    scanned_count = 0
    with_cves: list[tuple[object, list[str]]] = []
    all_cves: set[str] = set()
    for finding in qs.iterator(chunk_size=500):
        scanned_count += 1
        cves = sorted(extract_cves_with_origins(finding))
        if not cves:
            continue
        with_cves.append((finding, cves))
        all_cves.update(cves)
    return {"scanned_count": scanned_count, "with_cves": with_cves}, all_cves


# This function updates one Finding. This function needs matched KEV rows.
def _update_one_finding(
    *,
    finding,
    cves: list[str],
    rows_by_cve: dict[str, KevRow],
    first_dates: dict[str, dict[str, object]],
    settings: EPSSSettings,
) -> dict:
    matched_rows = [(cve, rows_by_cve[cve]) for cve in cves if cve in rows_by_cve]
    now = timezone.now()
    today = timezone.localdate(now)

    fu = FindingKEVUpdate.objects.filter(finding_id=finding.id).first()
    if not matched_rows:
        if fu and (fu.known_exploited or fu.ransomware_used):
            fu.status = EPSSStatus.MATCHED
            fu.reason = (
                "No current source match, but previous positive KEV state is "
                "preserved by positive-only mode."
            )
            fu.last_checked_at = now
            fu.save(update_fields=["status", "reason", "last_checked_at"])
        else:
            FindingKEVUpdate.objects.update_or_create(
                finding_id=finding.id,
                defaults={
                    "cve_id": cves[0],
                    "known_exploited": False,
                    "ransomware_used": False,
                    "status": EPSSStatus.SKIPPED,
                    "reason": f"No KEV data found for {len(cves)} CVE(s).",
                    "source_type": settings.kev_source_type,
                    "source_url": settings.kev_source_url,
                    "raw_data": {},
                    "last_checked_at": now,
                },
            )
        return {"matched": False, "updated": False}

    ransomware_rows = [(cve, row) for cve, row in matched_rows if row.ransomware_used]
    winning_cve, winning_row = (ransomware_rows or matched_rows)[0]
    ransomware_used = bool(ransomware_rows)

    kev_found_date = (
        getattr(fu, "kev_found_date", None)
        or _first_date_for([cve for cve, _ in matched_rows], first_dates, "kev")
        or today
    )
    ransomware_found_date = None
    if ransomware_used:
        ransomware_found_date = (
            getattr(fu, "ransomware_found_date", None)
            or _first_date_for([cve for cve, _ in ransomware_rows], first_dates, "ransomware")
            or today
        )

    Finding = get_finding_model()
    has_known = _model_has_field(Finding, "known_exploited")
    has_ransom = _model_has_field(Finding, "ransomware_used")
    has_kev_date = _model_has_field(Finding, "kev_date")

    update_fields = []
    if has_known and not getattr(finding, "known_exploited", False):
        finding.known_exploited = True
        update_fields.append("known_exploited")
    if has_ransom and ransomware_used and not getattr(finding, "ransomware_used", False):
        finding.ransomware_used = True
        update_fields.append("ransomware_used")
    if has_kev_date and not getattr(finding, "kev_date", None):
        finding.kev_date = kev_found_date
        update_fields.append("kev_date")

    with transaction.atomic():
        if update_fields:
            finding.save(update_fields=update_fields)
        fu, _ = FindingKEVUpdate.objects.get_or_create(finding_id=finding.id)
        fu.cve_id = winning_cve
        fu.known_exploited = True
        fu.ransomware_used = fu.ransomware_used or ransomware_used
        if not fu.kev_found_date:
            fu.kev_found_date = kev_found_date
        if ransomware_used and not fu.ransomware_found_date:
            fu.ransomware_found_date = ransomware_found_date
        fu.status = EPSSStatus.UPDATED if update_fields else EPSSStatus.MATCHED
        fu.reason = _matched_reason(matched_rows, ransomware_used, update_fields)
        fu.source_type = settings.kev_source_type
        fu.source_url = settings.kev_source_url
        fu.raw_data = winning_row.raw_data
        fu.last_checked_at = now
        if update_fields:
            fu.last_updated_at = now
        fu.save(update_fields=[
            "cve_id",
            "known_exploited",
            "ransomware_used",
            "kev_found_date",
            "ransomware_found_date",
            "status",
            "reason",
            "source_type",
            "source_url",
            "raw_data",
            "last_checked_at",
            "last_updated_at",
        ])

    return {"matched": True, "updated": bool(update_fields)}


# This function builds a match reason. This function needs matched rows and changed fields.
def _matched_reason(matched_rows: list[tuple[str, KevRow]], ransomware_used: bool, update_fields: list[str]) -> str:
    cve_preview = ", ".join(cve for cve, _ in matched_rows[:5])
    if len(matched_rows) > 5:
        cve_preview += "..."
    update_note = (
        f"updated Finding fields: {', '.join(update_fields)}"
        if update_fields
        else "Finding already had all positive KEV fields set"
    )
    ransomware_note = "ransomware signal present" if ransomware_used else "no ransomware signal present"
    return f"Matched {len(matched_rows)} KEV CVE(s): {cve_preview}; {ransomware_note}; {update_note}."


# This function reads first-found dates. This function needs CVE ids.
def _existing_first_dates(cves: Iterable[str]) -> dict[str, dict[str, object]]:
    out: dict[str, dict[str, object]] = {cve: {} for cve in cves}
    qs = FindingKEVUpdate.objects.filter(cve_id__in=list(out))
    for row in qs:
        bucket = out.setdefault(row.cve_id, {})
        if row.kev_found_date:
            current = bucket.get("kev")
            bucket["kev"] = min(current, row.kev_found_date) if current else row.kev_found_date
        if row.ransomware_found_date:
            current = bucket.get("ransomware")
            bucket["ransomware"] = (
                min(current, row.ransomware_found_date)
                if current else row.ransomware_found_date
            )
    return out


# This function returns the earliest stored date. This function needs CVEs and a date key.
def _first_date_for(cves: Iterable[str], first_dates: dict[str, dict[str, object]], key: str):
    values = [
        first_dates.get(cve, {}).get(key)
        for cve in cves
        if first_dates.get(cve, {}).get(key)
    ]
    return min(values) if values else None


# This function marks one KEV update failed. This function needs a Finding and error.
def _mark_failed(finding, cves: list[str], settings: EPSSSettings, exc: Exception) -> None:
    FindingKEVUpdate.objects.update_or_create(
        finding_id=finding.id,
        defaults={
            "cve_id": cves[0] if cves else "",
            "status": EPSSStatus.FAILED,
            "reason": f"KEV update error: {exc!s}"[:8000],
            "source_type": settings.kev_source_type,
            "source_url": settings.kev_source_url,
            "last_checked_at": timezone.now(),
        },
    )


# This function writes KEV stats to a log. This function needs stats and settings.
def _update_log(update_log: EPSSUpdateLog | None, stats: dict, settings: EPSSSettings) -> None:
    if update_log is None:
        return
    update_log.total_cves_fetched = stats["source_rows_seen"]
    update_log.total_cves_saved = stats["matched_cves"]
    update_log.total_findings_scanned = stats["scanned"]
    update_log.total_matches = stats["matched_findings"]
    update_log.total_findings_updated = stats["updated_findings"]
    update_log.total_skipped = stats["skipped"]
    update_log.total_failed = stats["failed"]
    update_log.details = {
        **(update_log.details or {}),
        "kev": {
            **stats.get("details", {}),
            "source_type": settings.kev_source_type,
            "source_url": settings.kev_source_url,
            "positive_updates_only": True,
        },
    }


# This function keeps valid Finding fields. This function needs field names.
def _safe_field_names(names: list[str]) -> list[str]:
    Finding = get_finding_model()
    out = []
    for n in names:
        try:
            Finding._meta.get_field(n)
            out.append(n)
        except Exception:
            continue
    return out


# This function finds valid CVE prefetch names. This function needs the Finding model.
def _safe_prefetch_names() -> list[str]:
    Finding = get_finding_model()
    out = []
    wanted = {"vulnerability_id_set", "vulnerability_ids"}
    for rel in Finding._meta.get_fields():
        try:
            accessor = rel.get_accessor_name()
        except Exception:
            continue
        if accessor in wanted:
            out.append(accessor)
            break
    return out


# This function checks if a model has a field. This function needs a model and field name.
def _model_has_field(model, name: str) -> bool:
    try:
        model._meta.get_field(name)
        return True
    except Exception:
        return False


# This function imports pghistory if available. This function needs installed dependencies.
def _import_pghistory():
    try:
        import pghistory  # type: ignore
        return pghistory
    except Exception:
        return None


# This function opens an audit context. This function needs optional pghistory.
@contextmanager
def _audit_context(pgh):
    if pgh is None:
        yield
    else:
        with pgh.context(source="dojo_epss.kev_update"):
            yield
