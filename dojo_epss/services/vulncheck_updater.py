"""VulnCheck POC / ITW matcher and updater."""

from __future__ import annotations

import datetime as _dt
import logging
from contextlib import contextmanager
from typing import Iterable

from django.db import transaction
from django.utils import timezone

from ..models import (
    EPSSSettings,
    EPSSStatus,
    EPSSUpdateLog,
    FindingVulnCheckUpdate,
)
from .finding_inventory import collect_finding_cves
from .http import EpssFetchError
from .vulncheck_client import VulnCheckClient, VulnCheckRow

log = logging.getLogger("dojo_epss.vulncheck_updater")


# This function syncs VulnCheck data to app-owned rows. This function needs settings.
def sync_vulncheck_findings(
    settings: EPSSSettings | None = None,
    update_log: EPSSUpdateLog | None = None,
) -> dict:
    s = settings or EPSSSettings.load()
    stats = {
        "scanned": 0,
        "with_cves": 0,
        "unique_cves": 0,
        "api_records_seen": 0,
        "api_requests": 0,
        "matched_cves": 0,
        "matched_findings": 0,
        "updated_findings": 0,
        "skipped": 0,
        "failed": 0,
        "details": {},
    }

    token = s.get_vulncheck_api_token()
    if not token:
        stats["details"]["skipped_reason"] = "VulnCheck API token is not configured"
        _update_log(update_log, stats, s)
        return stats

    inventory = collect_finding_cves(extra_fields=["severity", "active", "verified"])
    stats["scanned"] = inventory.scanned_count
    stats["with_cves"] = len(inventory.with_cves)
    stats["unique_cves"] = len(inventory.all_cves)

    if not inventory.all_cves:
        stats["details"]["skipped_reason"] = "no CVEs found in Findings"
        _update_log(update_log, stats, s)
        return stats

    client = VulnCheckClient(settings=s, token=token)
    fetch_result = client.fetch_cves(inventory.all_cves)
    rows_by_cve = fetch_result.rows_by_cve
    stats["api_records_seen"] = fetch_result.api_records_seen
    stats["api_requests"] = fetch_result.requests_made
    stats["matched_cves"] = len(rows_by_cve)
    stats["details"] = {
        "source_index": fetch_result.source_index,
        "unique_finding_cves": len(inventory.all_cves),
        "api_records_seen": fetch_result.api_records_seen,
        "api_requests": fetch_result.requests_made,
        "matched_cves_sample": sorted(rows_by_cve)[:100],
        "available_indexes_sample": fetch_result.available_indexes[:50],
        "positive_updates_only": True,
    }

    first_dates = _existing_first_dates(rows_by_cve.keys())
    pgh = _import_pghistory()

    with _audit_context(pgh):
        for finding, cves in inventory.with_cves:
            try:
                changed = _update_one_finding(
                    finding=finding,
                    cves=cves,
                    rows_by_cve=rows_by_cve,
                    first_dates=first_dates,
                    settings=s,
                )
            except Exception as exc:  # pylint: disable=broad-except
                log.exception("VulnCheck update failed for finding=%s", getattr(finding, "id", None))
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
    return stats


# This function updates one app-owned row. This function needs matched VulnCheck rows.
def _update_one_finding(
    *,
    finding,
    cves: list[str],
    rows_by_cve: dict[str, VulnCheckRow],
    first_dates: dict[str, dict[str, _dt.date]],
    settings: EPSSSettings,
) -> dict:
    matched_rows = [(cve, rows_by_cve[cve]) for cve in cves if cve in rows_by_cve]
    if not matched_rows:
        return {"matched": False, "updated": False}

    matched_rows.sort(
        key=lambda pair: (
            pair[1].exploit_in_the_wild,
            pair[1].weaponized_exploit_found,
            pair[1].public_exploit_found,
            pair[1].exploit_count,
        ),
        reverse=True,
    )
    winning_cve, winning_row = matched_rows[0]
    any_public = any(row.public_exploit_found for _, row in matched_rows)
    any_itw = any(row.exploit_in_the_wild for _, row in matched_rows)
    any_commercial = any(row.commercial_exploit_found for _, row in matched_rows)
    any_weaponized = any(row.weaponized_exploit_found for _, row in matched_rows)
    any_threat_actor = any(row.reported_exploited_by_threat_actors for _, row in matched_rows)
    any_ransomware = any(row.reported_exploited_by_ransomware for _, row in matched_rows)
    any_botnet = any(row.reported_exploited_by_botnets for _, row in matched_rows)
    any_honeypot = any(row.reported_exploited_by_honeypot_service for _, row in matched_rows)
    any_canary = any(row.reported_exploited_by_vulncheck_canaries for _, row in matched_rows)
    any_cisa_kev = any(row.in_cisa_kev for _, row in matched_rows)
    any_vulncheck_kev = any(row.in_vulncheck_kev for _, row in matched_rows)
    now = timezone.now()
    today = timezone.localdate(now)
    fu = FindingVulnCheckUpdate.objects.filter(finding_id=finding.id).first()

    poc_found_date = None
    if any_public:
        poc_found_date = (
            getattr(fu, "poc_found_date", None)
            or _first_date_for([cve for cve, row in matched_rows if row.public_exploit_found], first_dates, "poc")
            or _first_row_date(matched_rows, "poc")
            or today
        )

    itw_found_date = None
    if any_itw:
        itw_found_date = (
            getattr(fu, "itw_found_date", None)
            or _first_date_for([cve for cve, row in matched_rows if row.exploit_in_the_wild], first_dates, "itw")
            or _first_row_date(matched_rows, "itw")
            or today
        )

    with transaction.atomic():
        fu, created = FindingVulnCheckUpdate.objects.get_or_create(finding_id=finding.id)
        before_signal = (
            fu.public_exploit_found,
            fu.exploit_in_the_wild,
            fu.commercial_exploit_found,
            fu.weaponized_exploit_found,
            fu.reported_exploited_by_threat_actors,
            fu.reported_exploited_by_ransomware,
            fu.reported_exploited_by_botnets,
            fu.reported_exploited_by_honeypot_service,
            fu.reported_exploited_by_vulncheck_canaries,
            fu.in_cisa_kev,
            fu.in_vulncheck_kev,
        )
        fu.cve_id = winning_cve
        fu.public_exploit_found = fu.public_exploit_found or any_public
        fu.exploit_in_the_wild = fu.exploit_in_the_wild or any_itw
        fu.commercial_exploit_found = fu.commercial_exploit_found or any_commercial
        fu.weaponized_exploit_found = fu.weaponized_exploit_found or any_weaponized
        fu.reported_exploited_by_threat_actors = (
            fu.reported_exploited_by_threat_actors
            or any_threat_actor
        )
        fu.reported_exploited_by_ransomware = (
            fu.reported_exploited_by_ransomware
            or any_ransomware
        )
        fu.reported_exploited_by_botnets = (
            fu.reported_exploited_by_botnets
            or any_botnet
        )
        fu.reported_exploited_by_honeypot_service = (
            fu.reported_exploited_by_honeypot_service
            or any_honeypot
        )
        fu.reported_exploited_by_vulncheck_canaries = (
            fu.reported_exploited_by_vulncheck_canaries
            or any_canary
        )
        fu.in_cisa_kev = fu.in_cisa_kev or any_cisa_kev
        fu.in_vulncheck_kev = fu.in_vulncheck_kev or any_vulncheck_kev
        for _, row in matched_rows:
            fu.max_exploit_maturity = _stronger_maturity(
                fu.max_exploit_maturity,
                row.max_exploit_maturity,
            )
        if any_public and not fu.poc_found_date:
            fu.poc_found_date = poc_found_date
        if any_itw and not fu.itw_found_date:
            fu.itw_found_date = itw_found_date
        fu.exploit_count = max(
            fu.exploit_count or 0,
            max((row.exploit_count or 0 for _, row in matched_rows), default=0),
        )
        fu.source_index = settings.vulncheck_index
        merged_links = []
        for _, row in matched_rows:
            merged_links = _merge_links(merged_links, row.source_links)
        fu.source_links = _merge_links(fu.source_links, merged_links)
        fu.raw_data = winning_row.raw_data
        after_signal = (
            fu.public_exploit_found,
            fu.exploit_in_the_wild,
            fu.commercial_exploit_found,
            fu.weaponized_exploit_found,
            fu.reported_exploited_by_threat_actors,
            fu.reported_exploited_by_ransomware,
            fu.reported_exploited_by_botnets,
            fu.reported_exploited_by_honeypot_service,
            fu.reported_exploited_by_vulncheck_canaries,
            fu.in_cisa_kev,
            fu.in_vulncheck_kev,
        )
        updated = created or before_signal != after_signal
        fu.status = EPSSStatus.UPDATED if updated else EPSSStatus.MATCHED
        fu.reason = _matched_reason(matched_rows)
        fu.last_checked_at = now
        if updated:
            fu.last_updated_at = now
        fu.save(update_fields=[
            "cve_id",
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
            "source_index",
            "source_links",
            "raw_data",
            "status",
            "reason",
            "last_checked_at",
            "last_updated_at",
        ])

    return {"matched": True, "updated": updated}


# This function builds a match reason. This function needs matched rows.
def _matched_reason(matched_rows: list[tuple[str, VulnCheckRow]]) -> str:
    cve_preview = ", ".join(cve for cve, _ in matched_rows[:5])
    if len(matched_rows) > 5:
        cve_preview += "..."
    poc = sum(1 for _, row in matched_rows if row.public_exploit_found)
    itw = sum(1 for _, row in matched_rows if row.exploit_in_the_wild)
    return f"Matched {len(matched_rows)} VulnCheck CVE(s): {cve_preview}; POC={poc}; ITW={itw}."


# This function reads first-found dates. This function needs CVE ids.
def _existing_first_dates(cves: Iterable[str]) -> dict[str, dict[str, _dt.date]]:
    out: dict[str, dict[str, _dt.date]] = {cve: {} for cve in cves}
    for row in FindingVulnCheckUpdate.objects.filter(cve_id__in=list(out)):
        bucket = out.setdefault(row.cve_id, {})
        if row.poc_found_date:
            current = bucket.get("poc")
            bucket["poc"] = min(current, row.poc_found_date) if current else row.poc_found_date
        if row.itw_found_date:
            current = bucket.get("itw")
            bucket["itw"] = min(current, row.itw_found_date) if current else row.itw_found_date
    return out


# This function returns the earliest stored date. This function needs CVEs and a date key.
def _first_date_for(cves: Iterable[str], first_dates: dict[str, dict[str, _dt.date]], key: str):
    values = [
        first_dates.get(cve, {}).get(key)
        for cve in cves
        if first_dates.get(cve, {}).get(key)
    ]
    return min(values) if values else None


# This function returns the earliest row date. This function needs matched rows and a date key.
def _first_row_date(matched_rows: list[tuple[str, VulnCheckRow]], key: str):
    attr = "poc_found_date" if key == "poc" else "itw_found_date"
    values = [
        getattr(row, attr)
        for _, row in matched_rows
        if getattr(row, attr)
    ]
    return min(values) if values else None


# This function merges source links. This function needs existing and new links.
def _merge_links(existing, new_links) -> list[dict]:
    seen = set()
    out = []
    for link in [*(existing or []), *(new_links or [])]:
        if not isinstance(link, dict):
            continue
        key = (link.get("url") or link.get("reference_url") or link.get("name") or "")
        if key in seen:
            continue
        seen.add(key)
        out.append(link)
        if len(out) >= 25:
            break
    return out


# This function compares exploit maturity. This function needs two labels.
def _stronger_maturity(current: str, candidate: str) -> str:
    rank = {"": 0, "none": 0, "poc": 1, "weaponized": 2}
    current_key = str(current or "").strip().lower()
    candidate_key = str(candidate or "").strip().lower()
    return candidate if rank.get(candidate_key, 0) > rank.get(current_key, 0) else (current or candidate)


# This function marks one VulnCheck update failed. This function needs a Finding and error.
def _mark_failed(finding, cves: list[str], settings: EPSSSettings, exc: Exception) -> None:
    FindingVulnCheckUpdate.objects.update_or_create(
        finding_id=finding.id,
        defaults={
            "cve_id": cves[0] if cves else "",
            "status": EPSSStatus.FAILED,
            "reason": f"VulnCheck update error: {exc!s}"[:8000],
            "source_index": settings.vulncheck_index,
            "last_checked_at": timezone.now(),
        },
    )


# This function writes VulnCheck stats to a log. This function needs stats and settings.
def _update_log(update_log: EPSSUpdateLog | None, stats: dict, settings: EPSSSettings) -> None:
    if update_log is None:
        return
    update_log.total_cves_fetched = stats["unique_cves"]
    update_log.total_cves_saved = stats["matched_cves"]
    update_log.total_findings_scanned = stats["scanned"]
    update_log.total_matches = stats["matched_findings"]
    update_log.total_findings_updated = stats["updated_findings"]
    update_log.total_skipped = stats["skipped"]
    update_log.total_failed = stats["failed"]
    update_log.details = {
        **(update_log.details or {}),
        "vulncheck": {
            **stats.get("details", {}),
            "source_index": settings.vulncheck_index,
            "api_base_url": settings.vulncheck_api_base_url,
        },
    }


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
        with pgh.context(source="dojo_epss.vulncheck_update"):
            yield
