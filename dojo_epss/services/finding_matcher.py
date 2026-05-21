"""Finding matcher.

Walks every DefectDojo Finding, extracts each one's CVE id(s), and writes
a FindingEPSSUpdate row that records the outcome:

  status="matched"  — we have EPSS data for at least one of the CVEs;
                       the row stores the highest-EPSS one.
  status="skipped"  — Finding had CVE(s) but we don't have EPSS data for
                       any of them (FIRST.org hasn't published one).
  (no row written)  — Finding had no extractable CVEs at all (regex
                       matches nothing in any field).

This shape ensures the "EPSS Update" column on the Findings list reflects
*every* Finding we've considered, not just the ones that happened to
collide with our EPSSCVERecord cache. That fixes the user-visible bug
where Findings whose CVE isn't in EPSS would forever show "Not checked".

Never modifies Finding status, dedup, SLA, or notification fields.
"""

from __future__ import annotations

import logging
from typing import Iterable

from django.db import transaction
from django.utils import timezone

from ..models import (
    EPSSCVERecord,
    EPSSSettings,
    EPSSStatus,
    EPSSUpdateLog,
    FindingEPSSUpdate,
)
from ..queries import get_finding_model
from .cve_extractor import extract_cves_with_origins

log = logging.getLogger("dojo_epss.finding_matcher")


# This function compares Findings with EPSS records. This function needs EPSS data.
def compare(
    cve_records: Iterable[EPSSCVERecord] | None = None,
    settings: EPSSSettings | None = None,
    update_log: EPSSUpdateLog | None = None,
) -> dict:
    """Compare every Finding against the EPSS records in ``cve_records``
    (or all EPSSCVERecord rows, if omitted).

    Returns stats dict: ``{scanned, with_cves, matched, skipped, details}``.
    """
    s = settings or EPSSSettings.load()
    stats = {"scanned": 0, "with_cves": 0, "matched": 0, "skipped": 0, "details": {}}

    if not s.compare_against_findings_enabled:
        log.info("compare(): comparison disabled in settings — skipping.")
        if update_log is not None:
            update_log.total_skipped = (update_log.total_skipped or 0) + 1
        return stats

    # ---- build an EPSS lookup, keyed by upper-case CVE id, keeping the
    # row with the latest (date, score) per CVE.
    qs = cve_records if cve_records is not None else EPSSCVERecord.objects.all()
    epss_by_cve: dict[str, EPSSCVERecord] = {}
    for rec in qs:
        cve = rec.cve_id.upper()
        prev = epss_by_cve.get(cve)
        if prev is None or (rec.epss_date, rec.epss_score) > (prev.epss_date, prev.epss_score):
            epss_by_cve[cve] = rec

    # ---- walk every Finding (small DBs: fine; very large DBs: future
    # optimization could limit by recently-changed only).
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
        "severity",
        "active",
        "verified",
        "test_id",
    ])
    finding_qs = Finding.objects.all()
    if fields_we_use:
        finding_qs = finding_qs.only(*fields_we_use)
    prefetches = _safe_prefetch_names()
    if prefetches:
        finding_qs = finding_qs.prefetch_related(*prefetches)

    matched_record_ids: set[int] = set()
    details: dict[str, list[str]] = {}
    skipped_no_epss: dict[str, list[str]] = {}

    for finding in finding_qs.iterator(chunk_size=500):
        stats["scanned"] += 1
        cve_origins = extract_cves_with_origins(finding)
        if not cve_origins:
            # Finding has no extractable CVE; nothing to do, no row written.
            continue
        stats["with_cves"] += 1

        # Try to find EPSS data for any of the extracted CVEs.
        candidates: list[tuple[EPSSCVERecord, str]] = []
        for cve in cve_origins:
            rec = epss_by_cve.get(cve)
            if rec is not None:
                candidates.append((rec, cve))

        if candidates:
            # Pick highest EPSS for the canonical FindingEPSSUpdate.
            candidates.sort(key=lambda pair: (pair[0].epss_score, pair[0].epss_date), reverse=True)
            winning_record, winning_cve = candidates[0]
            matched_record_ids.add(winning_record.id)
            details[str(finding.id)] = [c for _, c in candidates]

            FindingEPSSUpdate.objects.update_or_create(
                finding_id=finding.id,
                defaults={
                    "cve_id": winning_cve,
                    "epss_score": winning_record.epss_score,
                    "epss_percentile": winning_record.epss_percentile,
                    "epss_date": winning_record.epss_date,
                    "status": EPSSStatus.MATCHED,
                    "reason": (
                        f"matched {len(candidates)} CVE(s) with EPSS data; "
                        f"selected highest EPSS={winning_record.epss_score}"
                    ),
                    "last_checked_at": timezone.now(),
                    "source_record": winning_record,
                },
            )
            stats["matched"] += 1
        else:
            # Finding has CVE(s) but no EPSS data for any of them.
            cves = list(cve_origins.keys())
            preview = ", ".join(cves[:5]) + ("…" if len(cves) > 5 else "")
            skipped_no_epss[str(finding.id)] = cves

            FindingEPSSUpdate.objects.update_or_create(
                finding_id=finding.id,
                defaults={
                    "cve_id": cves[0],
                    "epss_score": None,
                    "epss_percentile": None,
                    "epss_date": None,
                    "status": EPSSStatus.SKIPPED,
                    "reason": (
                        f"No EPSS data available for {len(cves)} CVE(s): {preview}. "
                        "Run 'FIRST.org fetch' first so this CVE is queried, "
                        "or check that the CVE id is correct."
                    ),
                    "last_checked_at": timezone.now(),
                    "source_record": None,
                },
            )
            stats["skipped"] += 1

    # ---- bookkeeping on the matched EPSSCVERecord rows.
    if matched_record_ids:
        with transaction.atomic():
            for rec_id in matched_record_ids:
                EPSSCVERecord.objects.filter(pk=rec_id).update(
                    matched_findings_count=_get_match_count(rec_id),
                    last_compared_at=timezone.now(),
                )

    stats["details"] = details
    if update_log is not None:
        update_log.total_findings_scanned = stats["scanned"]
        update_log.total_matches = stats["matched"]
        # Don't clobber a previously-set total_skipped — accumulate.
        update_log.total_skipped = (update_log.total_skipped or 0) + stats["skipped"]
        update_log.details = {
            **(update_log.details or {}),
            "findings_with_cves": stats["with_cves"],
            "findings_without_cves": stats["scanned"] - stats["with_cves"],
            "matched_finding_cves": details,
            "findings_skipped_no_epss_data": skipped_no_epss,
        }

    log.info(
        "compare(): scanned=%d with_cves=%d matched=%d skipped(no-epss)=%d",
        stats["scanned"], stats["with_cves"], stats["matched"], stats["skipped"],
    )
    return stats


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
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


# This function counts matches for a record. This function needs an EPSS record id.
def _get_match_count(record_id: int) -> int:
    return FindingEPSSUpdate.objects.filter(source_record_id=record_id).count()
