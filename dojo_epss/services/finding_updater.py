"""Finding updater.

Writes EPSS metadata back to ``Finding.epss_score`` / ``Finding.epss_percentile``
for findings that the matcher has EPSS data for AND that pass all configured
scope filters (req #10). Previously skipped rows with EPSS data are reconsidered
so loosening settings does not strand them forever.

Important guarantees:
  * Only ``epss_score`` and ``epss_percentile`` are ever written.
  * Writes go through ``Model.save(update_fields=[...])`` so concurrent edits
    to other Finding columns aren't clobbered.
  * Wrapped in ``pghistory.context(source="dojo_epss.auto_update")`` if
    pghistory is available, so the change appears in DefectDojo's audit log.
  * Supports dry-run mode that writes nothing but returns the same stats.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from decimal import Decimal
from typing import Iterable

from django.db import transaction
from django.utils import timezone

from ..models import (
    EPSSStatus,
    EPSSSettings,
    EPSSUpdateLog,
    FindingEPSSUpdate,
)
from ..queries import get_finding_model

log = logging.getLogger("dojo_epss.finding_updater")


# This function updates eligible Finding EPSS fields. This function needs matched rows.
def auto_update(
    settings: EPSSSettings | None = None,
    update_log: EPSSUpdateLog | None = None,
    dry_run: bool = False,
    finding_ids: Iterable[int] | None = None,
) -> dict:
    """Run auto-update over already-matched FindingEPSSUpdate rows.

    Stats returned: ``{updated, skipped, failed, dry_run}``.
    """
    s = settings or EPSSSettings.load()
    stats = {"updated": 0, "skipped": 0, "failed": 0, "dry_run": dry_run}

    if not s.auto_update_enabled and not dry_run:
        log.info("auto_update_enabled=False; skipping.")
        return stats

    qs = FindingEPSSUpdate.objects.select_related("finding").filter(
        status__in=[EPSSStatus.MATCHED, EPSSStatus.UPDATED, EPSSStatus.SKIPPED],
        epss_score__isnull=False,
    )
    if finding_ids is not None:
        qs = qs.filter(finding_id__in=list(finding_ids))

    Finding = get_finding_model()
    has_score = _model_has_field(Finding, "epss_score")
    has_pct = _model_has_field(Finding, "epss_percentile")
    if not (has_score or has_pct):
        log.warning("Finding has neither epss_score nor epss_percentile — auto-update is a no-op.")
        return stats

    pgh = _import_pghistory()

    with _audit_context(pgh):
        for fu in qs.iterator(chunk_size=200):
            decision, reason = _decide(fu, s)
            if decision == "skip":
                if not dry_run:
                    fu.status = EPSSStatus.SKIPPED
                    fu.reason = reason
                    fu.last_checked_at = timezone.now()
                    fu.save(update_fields=["status", "reason", "last_checked_at"])
                stats["skipped"] += 1
                continue

            if dry_run:
                stats["updated"] += 1
                continue

            try:
                with transaction.atomic():
                    finding = fu.finding
                    update_fields = []
                    if has_score and fu.epss_score is not None:
                        finding.epss_score = float(fu.epss_score)
                        update_fields.append("epss_score")
                    if has_pct and fu.epss_percentile is not None:
                        finding.epss_percentile = float(fu.epss_percentile)
                        update_fields.append("epss_percentile")
                    if update_fields:
                        finding.save(update_fields=update_fields)
                    fu.status = EPSSStatus.UPDATED
                    fu.reason = reason
                    fu.last_checked_at = timezone.now()
                    fu.last_updated_at = timezone.now()
                    fu.save(update_fields=["status", "reason", "last_checked_at", "last_updated_at"])
                stats["updated"] += 1
            except Exception as exc:  # pylint: disable=broad-except
                log.exception("auto-update failed for finding=%s", fu.finding_id)
                fu.status = EPSSStatus.FAILED
                fu.reason = f"update error: {exc!s}"[:8000]
                fu.last_checked_at = timezone.now()
                fu.save(update_fields=["status", "reason", "last_checked_at"])
                stats["failed"] += 1

    if update_log is not None:
        update_log.total_findings_updated = stats["updated"]
        update_log.total_skipped += stats["skipped"]
        update_log.total_failed = stats["failed"]
        update_log.details = {**(update_log.details or {}), "dry_run": dry_run}

    return stats


# ---------------------------------------------------------------------------
# Decision logic (req #10 scope filters)
# ---------------------------------------------------------------------------
# This function decides update or skip. This function needs a match row and settings.
def _decide(fu: FindingEPSSUpdate, s: EPSSSettings) -> tuple[str, str]:
    """Return (decision, reason) where decision ∈ {"update","skip"}."""
    finding = fu.finding

    # Score / percentile range
    if fu.epss_score is None:
        return "skip", "no epss_score on FindingEPSSUpdate"
    if not (s.update_min_epss_score <= fu.epss_score <= s.update_max_epss_score):
        return "skip", (
            f"epss {fu.epss_score} outside [{s.update_min_epss_score}, {s.update_max_epss_score}]"
        )
    if fu.epss_percentile is not None and not (
        s.update_min_percentile <= fu.epss_percentile <= s.update_max_percentile
    ):
        return "skip", (
            f"percentile {fu.epss_percentile} outside "
            f"[{s.update_min_percentile}, {s.update_max_percentile}]"
        )

    # Severity
    sevs = s.severities_list()
    if sevs:
        sev = getattr(finding, "severity", None)
        if sev not in sevs:
            return "skip", f"severity {sev!r} not in {sevs}"

    # Active / verified
    if s.update_active_findings_only:
        active = getattr(finding, "active", None)
        if active is False:
            return "skip", "finding is inactive (update_active_findings_only=True)"
    if s.update_verified_findings_only:
        verified = getattr(finding, "verified", None)
        if verified is False:
            return "skip", "finding is unverified (update_verified_findings_only=True)"

    # Product / Product Type allowlists
    p_ids = s.product_id_list()
    pt_ids = s.product_type_id_list()
    if p_ids or pt_ids:
        prod = _resolve_product(finding)
        if p_ids and (prod is None or getattr(prod, "id", None) not in p_ids):
            return "skip", "product not in allowlist"
        if pt_ids:
            pt_id = getattr(getattr(prod, "prod_type", None), "id", None)
            if pt_id is None or pt_id not in pt_ids:
                return "skip", "product_type not in allowlist"

    return "update", "scope filters passed"


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------
# This function checks if a model has a field. This function needs a model and field name.
def _model_has_field(model, name: str) -> bool:
    try:
        model._meta.get_field(name)
        return True
    except Exception:
        return False


# This function resolves a Finding product. This function needs a Finding.
def _resolve_product(finding):
    test = getattr(finding, "test", None)
    if test is None:
        return None
    eng = getattr(test, "engagement", None)
    if eng is None:
        return None
    return getattr(eng, "product", None)


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
        with pgh.context(source="dojo_epss.auto_update"):
            yield
