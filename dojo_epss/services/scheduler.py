"""Scheduler / orchestration helpers.

Exports:
  * ``full_sync_lock()``       — context manager backed by Django cache,
                                  prevents overlapping full-sync runs.
  * ``run_full_sync()``        — orchestrates fetch -> compare -> auto-update
                                  with one EPSSUpdateLog row per phase.

The installer wires a static ``dojo_epss.schedule_dispatcher_task`` entry into
``CELERY_BEAT_SCHEDULE``. The dispatcher reads UI-controlled interval fields
and calls this module only when EPSS is due.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Iterator

from django.core.cache import cache
from django.utils import timezone

from .. import app_settings
from ..models import (
    EPSSAction,
    EPSSLogStatus,
    EPSSSettings,
    EPSSUpdateLog,
)
from .epss_importer import import_csv, import_for_findings
from .finding_matcher import compare
from .finding_updater import auto_update
from .http import EpssFetchError

log = logging.getLogger("dojo_epss.scheduler")


# ---------------------------------------------------------------------------
# Concurrency lock
# ---------------------------------------------------------------------------
# This function prevents overlapping full syncs. This function needs Django cache.
@contextmanager
def full_sync_lock(timeout: int | None = None) -> Iterator[bool]:
    """Cache-based lock; ``yield`` is True only if we acquired it.

    Implementation note: ``cache.add`` is atomic (returns False if the key
    already exists), and works with all of DefectDojo's supported cache
    backends (Memcached, Redis, locmem, db). No external dependency.
    """
    ttl = timeout or app_settings.FULL_SYNC_LOCK_TTL_SECS
    acquired = cache.add(app_settings.FULL_SYNC_LOCK_KEY, "1", ttl)
    try:
        yield bool(acquired)
    finally:
        if acquired:
            cache.delete(app_settings.FULL_SYNC_LOCK_KEY)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
# This function runs EPSS fetch, compare, and update. This function needs valid settings.
def run_full_sync(
    user_id: int | None = None,
    use_csv: bool | None = None,
    use_threshold: bool | None = None,
) -> int | None:
    """Execute the full pipeline once. Returns the orchestrator log id.

    Sequence (per spec):
      1. Read EPSSSettings
      2. If module disabled, log skipped and exit
      3. Fetch recent or threshold CVEs (or CSV) according to settings
      4. Save EPSSCVERecord rows  (handled inside epss_importer)
      5. Compare against Findings if compare_against_findings_enabled
      6. Update eligible Findings if auto_update_enabled
      7. Write EPSSUpdateLog
    """
    s = EPSSSettings.load()
    active_source = s.active_fetch_source()
    orchestrator = EPSSUpdateLog.objects.create(
        action=EPSSAction.DOWNLOAD_CSV if active_source == "csv" else EPSSAction.FETCH_BATCH,
        status=EPSSLogStatus.STARTED,
        requested_by_id=user_id,
        request_params=_settings_snapshot(s),
    )

    if not s.enabled:
        orchestrator.mark_finished(EPSSLogStatus.SKIPPED, error="EPSS module disabled (settings.enabled=False).")
        return orchestrator.id

    # Honor schedule_enabled when invoked from Celery beat. Manual invocations
    # (anything that doesn't pass user_id=None *and* has user context) bypass
    # this gate — the operator clicked a button, they want it to run now.
    invoked_by_beat = (user_id is None)
    if invoked_by_beat and not s.schedule_enabled:
        orchestrator.mark_finished(
            EPSSLogStatus.SKIPPED,
            error="Scheduled runs disabled (settings.schedule_enabled=False). "
                  "Manual runs still work.",
        )
        return orchestrator.id

    with full_sync_lock() as acquired:
        if not acquired:
            log.warning("run_full_sync: another full sync is in progress; skipping.")
            orchestrator.mark_finished(
                EPSSLogStatus.SKIPPED,
                error="another full sync is already running (lock held)",
            )
            return orchestrator.id

        if active_source not in {"firstorg", "csv"}:
            orchestrator.mark_finished(
                EPSSLogStatus.SKIPPED,
                error="Exactly one EPSS fetch source must be enabled in settings.",
            )
            return orchestrator.id

        requested_source = "csv" if use_csv else "firstorg" if use_csv is False else active_source
        if requested_source != active_source:
            orchestrator.mark_finished(
                EPSSLogStatus.SKIPPED,
                error=(
                    f"Requested source {requested_source!r} does not match "
                    f"enabled source {active_source!r}."
                ),
            )
            return orchestrator.id

        try:
            # --- fetch ---
            if active_source == "csv":
                _, rows, written = import_csv(settings=s, update_log=orchestrator)
            else:
                rows, written, cve_count = import_for_findings(settings=s)
                orchestrator.details = {
                    **(orchestrator.details or {}),
                    "phase1_fetch": {
                        "source": "first.org REST (per-CVE)",
                        "unique_cves_in_findings": cve_count,
                        "cves_with_epss_data": len(rows),
                        "cves_without_epss_data": cve_count - len(rows),
                    },
                }
            orchestrator.total_cves_fetched = len(rows)
            orchestrator.total_cves_saved = written

            # --- compare ---
            if s.compare_against_findings_enabled:
                m_stats = compare(settings=s, update_log=orchestrator)
                orchestrator.total_findings_scanned = m_stats["scanned"]
                orchestrator.total_matches = m_stats["matched"]

            # --- auto-update ---
            if s.auto_update_enabled:
                u_stats = auto_update(settings=s, update_log=orchestrator)
                orchestrator.total_findings_updated = u_stats["updated"]
                orchestrator.total_skipped = u_stats["skipped"]
                orchestrator.total_failed = u_stats["failed"]

            outcome = (
                EPSSLogStatus.SUCCESS
                if orchestrator.total_failed == 0
                else EPSSLogStatus.PARTIAL_SUCCESS
            )
            orchestrator.mark_finished(outcome)
        except EpssFetchError as exc:
            orchestrator.mark_finished(EPSSLogStatus.FAILED, error=str(exc))
        except Exception as exc:  # pylint: disable=broad-except
            orchestrator.mark_finished(EPSSLogStatus.FAILED, error=f"unexpected: {exc!s}")

    return orchestrator.id


# This function records settings in a log. This function needs loaded settings.
def _settings_snapshot(s: EPSSSettings) -> dict:
    return {
        "api_base_url": s.api_base_url,
        "csv_base_url": s.csv_base_url,
        "epss_score_threshold": str(s.epss_score_threshold) if s.epss_score_threshold else None,
        "epss_percentile_threshold": str(s.epss_percentile_threshold) if s.epss_percentile_threshold else None,
        "fetch_date": s.fetch_date.isoformat() if s.fetch_date else None,
        "result_limit": s.result_limit,
        "order_by_epss_desc": s.order_by_epss_desc,
        "fetch_recent_enabled": s.fetch_recent_enabled,
        "download_full_csv_enabled": s.download_full_csv_enabled,
        "active_fetch_source": s.active_fetch_source(),
        "compare_against_findings_enabled": s.compare_against_findings_enabled,
        "auto_update_enabled": s.auto_update_enabled,
    }
