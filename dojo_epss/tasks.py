"""Celery tasks for dojo_epss.

Designed to slot into DefectDojo's existing Celery setup. We import
``app`` from ``dojo.celery`` when available so our tasks share the same
worker, queue, and DojoAsyncTask base. Falls back to a ``shared_task``
decorator (or no-op) when Celery / dojo isn't importable.

Every task creates an ``EPSSUpdateLog`` row and never lets an exception
escape — failures are recorded with status="failed" and the worker exits
cleanly so the broker can move on.
"""

from __future__ import annotations

import datetime as _dt
import logging
from contextlib import contextmanager

from django.core.cache import cache
from django.utils import timezone

from . import app_settings
from .models import (
    EPSSAction,
    EPSSLogStatus,
    EPSSSettings,
    EPSSUpdateLog,
)
from .services.epss_importer import (
    import_csv,
    import_for_findings,
)
from .services.finding_matcher import compare
from .services.finding_updater import auto_update
from .services.http import EpssFetchError
from .services.kev_updater import sync_kev_findings
from .services.scheduler import run_full_sync

log = logging.getLogger("dojo_epss.tasks")


# ---------------------------------------------------------------------------
# Resolve a task decorator that works with or without dojo.celery available.
# ---------------------------------------------------------------------------
try:
    from dojo.celery import app as _dojo_app  # type: ignore

    def epss_task(name: str):
        return _dojo_app.task(bind=True, name=name)
except Exception:  # pragma: no cover - dev / docs / test envs
    try:
        from celery import shared_task  # type: ignore

        def epss_task(name: str):
            return shared_task(bind=True, name=name)
    except Exception:
        def epss_task(name: str):  # type: ignore
            def deco(fn):
                return fn
            return deco


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
# This function creates an update log. This function needs an action and params.
def _start_log(action: str, params: dict, user_id: int | None = None) -> EPSSUpdateLog:
    return EPSSUpdateLog.objects.create(
        action=action,
        status=EPSSLogStatus.STARTED,
        request_params=params,
        requested_by_id=user_id,
    )


# This function logs a disabled module skip. This function needs an action.
def _settings_disabled_log(action: str, user_id: int | None = None) -> int:
    log_row = _start_log(action, {"reason": "EPSS module disabled"}, user_id=user_id)
    log_row.mark_finished(EPSSLogStatus.SKIPPED, error="EPSS module disabled (settings.enabled=False).")
    return log_row.id


# This function logs a disabled fetch source skip. This function needs expected and actual sources.
def _fetch_source_skipped_log(
    action: str,
    expected: str,
    actual: str,
    user_id: int | None = None,
) -> int:
    label = "FIRST.org" if expected == "firstorg" else "daily CSV"
    log_row = _start_log(
        action,
        {"expected_source": expected, "actual_source": actual},
        user_id=user_id,
    )
    log_row.mark_finished(
        EPSSLogStatus.SKIPPED,
        error=f"{label} source is not enabled in EPSS Settings.",
    )
    return log_row.id


# This function prevents overlapping KEV syncs. This function needs Django cache.
@contextmanager
def _kev_sync_lock():
    acquired = cache.add(
        app_settings.KEV_SYNC_LOCK_KEY,
        "1",
        app_settings.KEV_SYNC_LOCK_TTL_SECS,
    )
    try:
        yield bool(acquired)
    finally:
        if acquired:
            cache.delete(app_settings.KEV_SYNC_LOCK_KEY)


# This function prevents overlapping scheduler ticks. This function needs Django cache.
@contextmanager
def _schedule_dispatcher_lock():
    acquired = cache.add(
        app_settings.SCHEDULE_DISPATCHER_LOCK_KEY,
        "1",
        app_settings.SCHEDULE_DISPATCHER_LOCK_TTL_SECS,
    )
    try:
        yield bool(acquired)
    finally:
        if acquired:
            cache.delete(app_settings.SCHEDULE_DISPATCHER_LOCK_KEY)


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------
# Legacy tasks (epss_fetch_recent_task, epss_fetch_threshold_task) were
# removed in the finding-driven refactor — they used the catalog-driven
# import paths that produced no useful output for typical DefectDojo
# installs. Use epss_fetch_findings_task (FIRST.org button) or
# epss_download_csv_task (CSV button) instead. Manual fetch tasks run
# fetch/download → compare; auto-update stays as an explicit action.

@epss_task(name="dojo_epss.epss_fetch_threshold_task_placeholder")
def _placeholder(self, *args, **kwargs):  # pragma: no cover
    """Kept under a renamed Celery name so any operator who has the
    old task name pinned in their Celery beat schedule gets a clean
    skipped log row instead of an ImportError. Remove in 1.0."""
    return None


# This task fetches EPSS for Finding CVEs. This task needs FIRST.org source enabled.
@epss_task(name="dojo_epss.epss_fetch_findings_task")
def epss_fetch_findings_task(self, *, user_id: int | None = None):  # noqa: ARG001
    """PRIMARY USE CASE — finding-driven fetch + compare.

    Two phases, under one log row:
      1. fetch   — extract CVEs from every Finding, batch-query FIRST.org,
                   upsert into EPSSCVERecord.
      2. compare — walk every Finding-with-CVE; write FindingEPSSUpdate
                   with status=matched (have EPSS data) OR status=skipped
                   (CVE not in EPSS). This is what populates the
                   'EPSS Update' column on the Findings list.
    Auto-update is deliberately left to epss_auto_update_findings_task so the
    operator can review matches before changing Finding fields.
    """
    s = EPSSSettings.load()
    if not s.enabled:
        return _settings_disabled_log(EPSSAction.FETCH_BATCH, user_id=user_id)
    active_source = s.active_fetch_source()
    if active_source != "firstorg":
        return _fetch_source_skipped_log(
            EPSSAction.FETCH_BATCH,
            expected="firstorg",
            actual=active_source,
            user_id=user_id,
        )

    log_row = _start_log(EPSSAction.FETCH_BATCH, {"mode": "finding_driven_pipeline"}, user_id=user_id)

    # ---- phase 1: fetch
    try:
        rows, written, cve_count = import_for_findings(settings=s)
        log_row.total_cves_fetched = len(rows)
        log_row.total_cves_saved = written
        log_row.details = {
            **(log_row.details or {}),
            "phase1_fetch": {
                "source": "first.org REST (per-CVE)",
                "unique_cves_in_findings": cve_count,
                "cves_with_epss_data": len(rows),
                "cves_without_epss_data": cve_count - len(rows),
            },
        }
    except EpssFetchError as exc:
        log_row.mark_finished(EPSSLogStatus.FAILED, error=f"fetch failed: {exc}")
        return log_row.id
    except Exception as exc:  # pylint: disable=broad-except
        log_row.mark_finished(EPSSLogStatus.FAILED, error=f"fetch unexpected: {exc!s}")
        return log_row.id

    # Manual FIRST.org action is intentionally fetch + compare. Auto-update is
    # kept as a separate explicit action on the Manual Run page.
    final_status = _run_compare_and_update_phases(s, log_row, include_update=False)
    log_row.mark_finished(final_status)
    return log_row.id


# This function runs compare and optional update phases. This function needs settings and a log.
def _run_compare_and_update_phases(
    s: EPSSSettings,
    log_row,
    *,
    include_update: bool = True,
) -> str:
    """Run compare, and optionally auto-update, against the current
    EPSSCVERecord cache. Manual fetch tasks call this with include_update=False;
    scheduled full sync keeps the auto-update phase enabled by settings.
    """
    status = EPSSLogStatus.SUCCESS

    if s.compare_against_findings_enabled:
        try:
            c_stats = compare(settings=s, update_log=log_row)
            log_row.details = {
                **(log_row.details or {}),
                "phase2_compare": c_stats,
            }
        except Exception as exc:  # pylint: disable=broad-except
            status = EPSSLogStatus.PARTIAL_SUCCESS
            log_row.error_message = (log_row.error_message or "") + f"\ncompare failed: {exc!s}"
    else:
        log_row.details = {
            **(log_row.details or {}),
            "phase2_compare": "skipped (compare_against_findings_enabled=False)",
        }

    if include_update and s.auto_update_enabled:
        try:
            u_stats = auto_update(settings=s, update_log=log_row)
            log_row.total_findings_updated = u_stats["updated"]
            log_row.total_failed = u_stats["failed"]
            log_row.details = {
                **(log_row.details or {}),
                "phase3_auto_update": u_stats,
            }
            if u_stats["failed"] > 0:
                status = EPSSLogStatus.PARTIAL_SUCCESS
        except Exception as exc:  # pylint: disable=broad-except
            status = EPSSLogStatus.PARTIAL_SUCCESS
            log_row.error_message = (log_row.error_message or "") + f"\nauto_update failed: {exc!s}"
    elif not include_update:
        log_row.details = {
            **(log_row.details or {}),
            "phase3_auto_update": "skipped (manual fetch/compare action)",
        }

    return status


# This task downloads EPSS CSV data. This task needs CSV source enabled.
@epss_task(name="dojo_epss.epss_download_csv_task")
def epss_download_csv_task(self, score_date_iso: str | None = None,
                           *, user_id: int | None = None):  # noqa: ARG001
    """CSV download path — download + compare.

    The manual CSV button downloads/upserts EPSS rows, then compares them
    against Findings. Updating eligible Finding fields remains a separate
    explicit action.
    """
    s = EPSSSettings.load()
    if not s.enabled:
        return _settings_disabled_log(EPSSAction.DOWNLOAD_CSV, user_id=user_id)
    active_source = s.active_fetch_source()
    if active_source != "csv":
        return _fetch_source_skipped_log(
            EPSSAction.DOWNLOAD_CSV,
            expected="csv",
            actual=active_source,
            user_id=user_id,
        )
    target = _dt.date.fromisoformat(score_date_iso) if score_date_iso else None
    log_row = _start_log(EPSSAction.DOWNLOAD_CSV, {"date": score_date_iso}, user_id=user_id)

    # ---- phase 1: download CSV
    try:
        final_date, rows, written = import_csv(target, settings=s, update_log=log_row)
        log_row.total_cves_fetched = len(rows)
        log_row.total_cves_saved = written
        log_row.details = {
            **(log_row.details or {}),
            "phase1_fetch": {
                "source": f"FIRST.org daily CSV ({final_date})",
                "rows_in_csv": len(rows),
                "rows_upserted": written,
            },
        }
    except EpssFetchError as exc:
        log_row.mark_finished(EPSSLogStatus.FAILED, error=str(exc))
        return log_row.id
    except Exception as exc:  # pylint: disable=broad-except
        log_row.mark_finished(EPSSLogStatus.FAILED, error=f"unexpected: {exc!s}")
        return log_row.id

    # Manual CSV action is intentionally download + compare. Auto-update is kept
    # as a separate explicit action on the Manual Run page.
    final_status = _run_compare_and_update_phases(s, log_row, include_update=False)
    log_row.mark_finished(final_status)
    return log_row.id


# This task compares EPSS records with Findings. This task needs EPSS records.
@epss_task(name="dojo_epss.epss_compare_findings_task")
def epss_compare_findings_task(self, *, user_id: int | None = None):  # noqa: ARG001
    s = EPSSSettings.load()
    if not s.enabled:
        return _settings_disabled_log(EPSSAction.COMPARE, user_id=user_id)
    log_row = _start_log(EPSSAction.COMPARE, {}, user_id=user_id)
    try:
        stats = compare(settings=s, update_log=log_row)
        log_row.total_findings_scanned = stats["scanned"]
        log_row.total_matches = stats["matched"]
        log_row.mark_finished(EPSSLogStatus.SUCCESS)
    except Exception as exc:  # pylint: disable=broad-except
        log_row.mark_finished(EPSSLogStatus.FAILED, error=f"unexpected: {exc!s}")
    return log_row.id


# This task updates eligible Findings. This task needs matched Finding rows.
@epss_task(name="dojo_epss.epss_auto_update_findings_task")
def epss_auto_update_findings_task(self, dry_run: bool = False,
                                   *, user_id: int | None = None):  # noqa: ARG001
    s = EPSSSettings.load()
    if not s.enabled:
        return _settings_disabled_log(EPSSAction.AUTO_UPDATE, user_id=user_id)
    log_row = _start_log(EPSSAction.AUTO_UPDATE, {"dry_run": dry_run}, user_id=user_id)
    try:
        stats = auto_update(settings=s, update_log=log_row, dry_run=dry_run)
        log_row.total_findings_updated = stats["updated"]
        log_row.total_skipped = stats["skipped"]
        log_row.total_failed = stats["failed"]
        outcome = (
            EPSSLogStatus.SUCCESS if stats["failed"] == 0 else EPSSLogStatus.PARTIAL_SUCCESS
        )
        log_row.mark_finished(outcome)
    except Exception as exc:  # pylint: disable=broad-except
        log_row.mark_finished(EPSSLogStatus.FAILED, error=f"unexpected: {exc!s}")
    return log_row.id


# This task runs the full EPSS sync. This task needs valid EPSS settings.
@epss_task(name="dojo_epss.epss_full_sync_task")
def epss_full_sync_task(self, use_csv: bool | None = None,
                        use_threshold: bool | None = None,
                        *, user_id: int | None = None):  # noqa: ARG001
    return run_full_sync(user_id=user_id, use_csv=use_csv, use_threshold=use_threshold)


# This task runs the full KEV sync. This task needs KEV settings enabled.
@epss_task(name="dojo_epss.kev_full_sync_task")
def kev_full_sync_task(self, *, user_id: int | None = None):  # noqa: ARG001
    return _run_kev_full_sync(user_id=user_id, enforce_schedule_gate=(user_id is None))


# This function performs KEV sync work. This function needs settings and a lock.
def _run_kev_full_sync(
    *,
    user_id: int | None = None,
    enforce_schedule_gate: bool = True,
) -> int:
    s = EPSSSettings.load()
    log_row = _start_log(
        EPSSAction.KEV_SYNC,
        {
            "source_type": s.kev_source_type,
            "source_url": s.kev_source_url,
            "positive_updates_only": True,
        },
        user_id=user_id,
    )

    if not s.enabled:
        log_row.mark_finished(EPSSLogStatus.SKIPPED, error="EPSS/KEV module disabled (settings.enabled=False).")
        return log_row.id
    if not s.kev_enabled:
        log_row.mark_finished(EPSSLogStatus.SKIPPED, error="KEV checks disabled (settings.kev_enabled=False).")
        return log_row.id
    if not s.kev_update_findings_enabled:
        log_row.mark_finished(
            EPSSLogStatus.SKIPPED,
            error="KEV Finding updates disabled (settings.kev_update_findings_enabled=False).",
        )
        return log_row.id

    if enforce_schedule_gate and not s.kev_schedule_enabled:
        log_row.mark_finished(
            EPSSLogStatus.SKIPPED,
            error="Scheduled KEV runs disabled (settings.kev_schedule_enabled=False). Manual runs still work.",
        )
        return log_row.id

    with _kev_sync_lock() as acquired:
        if not acquired:
            log_row.mark_finished(EPSSLogStatus.SKIPPED, error="another KEV sync is already running (lock held)")
            return log_row.id

        try:
            stats = sync_kev_findings(settings=s, update_log=log_row)
            outcome = EPSSLogStatus.SUCCESS if stats["failed"] == 0 else EPSSLogStatus.PARTIAL_SUCCESS
            log_row.mark_finished(outcome)
        except EpssFetchError as exc:
            log_row.mark_finished(EPSSLogStatus.FAILED, error=str(exc))
        except Exception as exc:  # pylint: disable=broad-except
            log.exception("KEV full sync failed")
            log_row.mark_finished(EPSSLogStatus.FAILED, error=f"unexpected: {exc!s}")
    return log_row.id


# This task checks scheduled EPSS and KEV work. This task needs Celery beat.
@epss_task(name="dojo_epss.schedule_dispatcher_task")
def schedule_dispatcher_task(self):  # noqa: ARG001
    """Hourly lightweight scheduler.

    Celery beat calls this static task. The task reads EPSSSettings and only
    runs EPSS/KEV syncs when their UI-controlled 12h/24h interval is due.
    Not-due ticks do not create EPSSUpdateLog rows.
    """
    s = EPSSSettings.load()
    result = {"epss": "not_due", "kev": "not_due"}

    if not s.enabled:
        return {"module": "disabled", **result}

    with _schedule_dispatcher_lock() as acquired:
        if not acquired:
            return {"dispatcher": "locked", **result}

        now = timezone.now()
        if s.schedule_enabled and _interval_due(
            s.epss_last_scheduled_run_at,
            s.schedule_interval_hours,
            now,
        ):
            EPSSSettings.objects.filter(pk=s.pk).update(epss_last_scheduled_run_at=now)
            result["epss"] = run_full_sync(user_id=None)

        if s.kev_enabled and s.kev_schedule_enabled and _interval_due(
            s.kev_last_scheduled_run_at,
            s.kev_schedule_interval_hours,
            now,
        ):
            EPSSSettings.objects.filter(pk=s.pk).update(kev_last_scheduled_run_at=now)
            result["kev"] = _run_kev_full_sync(user_id=None, enforce_schedule_gate=True)

    return result


# This function checks if an interval is due. This function needs the last run time.
def _interval_due(last_run, interval_hours, now) -> bool:
    try:
        hours = int(interval_hours)
    except (TypeError, ValueError):
        hours = 24
    if hours not in {12, 24}:
        hours = 24
    if last_run is None:
        return True
    return now - last_run >= _dt.timedelta(hours=hours)


# Suggested Celery beat entry to add to local_settings.py / settings.dist.py:
# the installer generates this static hourly dispatcher. The dispatcher reads
# EPSSSettings.schedule_interval_hours / kev_schedule_interval_hours and only
# runs EPSS/KEV when the UI-controlled interval is due.
#
# from datetime import timedelta
# CELERY_BEAT_SCHEDULE = {
#     **CELERY_BEAT_SCHEDULE,
#     "dojo_epss-schedule-dispatcher-hourly": {
#         "task": "dojo_epss.schedule_dispatcher_task",
#         "schedule": crontab(minute="7"),
#         "options": {"expires": int(60 * 30)},
#     },
# }
