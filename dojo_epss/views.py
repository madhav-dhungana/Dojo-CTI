"""Views for the EPSS management section.

Six read-only pages + one settings page + a manual-run page + POST
action endpoints. Action endpoints prefer Celery (.delay) when the task
function exposes one; otherwise they run inline so the operator sees
results immediately.

Every action that writes — manual or scheduled — creates an EPSSUpdateLog
row, satisfying the spec's audit-log requirement.
"""

from __future__ import annotations

import datetime as _dt
import logging
from functools import wraps

from django.contrib import messages
from django.core.paginator import Paginator
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.views.decorators.http import require_POST

from .forms import EPSSSettingsForm
from .models import (
    EPSSAction,
    EPSSDownloadBatch,
    EPSSLogStatus,
    EPSSSettings,
    EPSSStatus,
    EPSSUpdateLog,
    FindingEPSSUpdate,
    FindingKEVUpdate,
)
from .permissions import superuser_required, view_or_perm
from .services.first_client import FirstEPSSClient
from . import tasks as epss_tasks

log = logging.getLogger("dojo_epss.views")


# ---------------------------------------------------------------------------
# Breadcrumb helper — uses DefectDojo's add_breadcrumb when available so the
# EPSS pages slot into the existing breadcrumb bar instead of stacking a
# second one on top.
# ---------------------------------------------------------------------------
def _crumb(request, title: str) -> None:
    """Set the breadcrumb to 'EPSS / <title>' via DefectDojo's helper.

    top_level=True RESETS the session-tracked breadcrumb chain so clicking
    around the EPSS section doesn't accumulate stale crumbs from earlier
    pages (e.g. /finding/open). Falls back silently if dojo isn't importable
    (test environments using the fake_dojo stub).
    """
    try:
        from dojo.utils import add_breadcrumb
    except Exception:
        return
    try:
        add_breadcrumb(title=f"EPSS / {title}", top_level=True, request=request)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 1) Dashboard
# ---------------------------------------------------------------------------
# This view shows EPSS and KEV summary data. This view needs dashboard access.
@view_or_perm()
def dashboard(request: HttpRequest) -> HttpResponse:
    _crumb(request, "Dashboard")
    s = EPSSSettings.load()
    last_runs = EPSSUpdateLog.objects.order_by("-started_at")[:10]

    last_fetch = (
        EPSSUpdateLog.objects.filter(
            action__in=[
                EPSSAction.FETCH_RECENT, EPSSAction.FETCH_THRESHOLD,
                EPSSAction.FETCH_BATCH, EPSSAction.DOWNLOAD_CSV,
            ],
            status__in=[EPSSLogStatus.SUCCESS, EPSSLogStatus.PARTIAL_SUCCESS],
        ).order_by("-started_at").first()
    )
    last_compare = (
        EPSSUpdateLog.objects.filter(action=EPSSAction.COMPARE)
        .order_by("-started_at").first()
    )
    last_update = (
        EPSSUpdateLog.objects.filter(action=EPSSAction.AUTO_UPDATE)
        .order_by("-started_at").first()
    )
    last_kev = (
        EPSSUpdateLog.objects.filter(action=EPSSAction.KEV_SYNC)
        .order_by("-started_at").first()
    )

    counts = {
        "matches": FindingEPSSUpdate.objects.exclude(status=EPSSStatus.NOT_CHECKED).count(),
        "updated": FindingEPSSUpdate.objects.filter(status=EPSSStatus.UPDATED).count(),
        "failed": FindingEPSSUpdate.objects.filter(status=EPSSStatus.FAILED).count(),
        "skipped": FindingEPSSUpdate.objects.filter(status=EPSSStatus.SKIPPED).count(),
    }
    kev_counts = {
        "matches": FindingKEVUpdate.objects.filter(known_exploited=True).count(),
        "ransomware": FindingKEVUpdate.objects.filter(ransomware_used=True).count(),
        "updated": FindingKEVUpdate.objects.filter(status=EPSSStatus.UPDATED).count(),
        "failed": FindingKEVUpdate.objects.filter(status=EPSSStatus.FAILED).count(),
    }
    top_matches = list(
        FindingEPSSUpdate.objects.exclude(status=EPSSStatus.NOT_CHECKED)
        .select_related("finding").order_by("-epss_score")[:10]
    )
    kev_by_finding = {
        row.finding_id: row
        for row in FindingKEVUpdate.objects.filter(
            finding_id__in=[fu.finding_id for fu in top_matches],
        )
    }
    for fu in top_matches:
        fu.kev_snapshot = kev_by_finding.get(fu.finding_id)

    return render(request, "dojo_epss/dashboard.html", {
        "settings": s,
        "last_runs": last_runs,
        "last_fetch": last_fetch,
        "last_compare": last_compare,
        "last_update": last_update,
        "last_kev": last_kev,
        "counts": counts,
        "kev_counts": kev_counts,
        "top_matches": top_matches,
    })


# ---------------------------------------------------------------------------
# 2) Settings
# ---------------------------------------------------------------------------
# This view edits EPSS and KEV settings. This view needs a superuser.
@superuser_required
def settings_edit(request: HttpRequest) -> HttpResponse:
    _crumb(request, "Settings")
    s = EPSSSettings.load()
    if request.method == "POST":
        form = EPSSSettingsForm(request.POST, instance=s)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.updated_by = request.user
            obj.save()
            messages.success(request, "EPSS / KEV settings saved.")
            return HttpResponseRedirect(reverse("dojo_epss:settings"))
    else:
        form = EPSSSettingsForm(instance=s)
    return render(request, "dojo_epss/settings.html", {"form": form, "settings": s})


# ---------------------------------------------------------------------------
# 3) CVE Records
# ---------------------------------------------------------------------------
# cve_records / cve_detail views were removed in the finding-driven refactor.
# If something still resolves to those template names, the stub templates
# (templates/dojo_epss/cve_records.html / cve_detail.html) render a soft
# "page removed" notice instead of 500-ing.


# ---------------------------------------------------------------------------
# 4) Finding Matches
# ---------------------------------------------------------------------------
# This view lists Finding EPSS matches. This view needs dashboard access.
@view_or_perm()
def finding_matches(request: HttpRequest) -> HttpResponse:
    _crumb(request, "Finding Matches")
    qs = (FindingEPSSUpdate.objects
          .exclude(status=EPSSStatus.NOT_CHECKED)
          .select_related("finding", "source_record")
          .order_by("-last_checked_at"))

    status = request.GET.get("status")
    if status:
        qs = qs.filter(status=status)

    page = Paginator(qs, 50).get_page(request.GET.get("page"))
    kev_by_finding = {
        row.finding_id: row
        for row in FindingKEVUpdate.objects.filter(
            finding_id__in=[fu.finding_id for fu in page.object_list],
        )
    }
    for fu in page.object_list:
        fu.kev_snapshot = kev_by_finding.get(fu.finding_id)

    return render(request, "dojo_epss/finding_matches.html", {
        "page": page,
        "current_status": status,
        "status_choices": EPSSStatus.choices,
    })


# ---------------------------------------------------------------------------
# 5) Update Logs
# ---------------------------------------------------------------------------
# This view lists EPSS and KEV update logs. This view needs dashboard access.
@view_or_perm()
def update_logs(request: HttpRequest) -> HttpResponse:
    _crumb(request, "Update Logs")
    qs = EPSSUpdateLog.objects.all().order_by("-started_at")
    action = request.GET.get("action")
    if action:
        qs = qs.filter(action=action)
    page = Paginator(qs, 50).get_page(request.GET.get("page"))
    return render(request, "dojo_epss/logs.html", {
        "page": page,
        "current_action": action,
        "action_choices": EPSSAction.choices,
    })


# This view shows one update log. This view needs a log id.
@view_or_perm()
def update_log_detail(request: HttpRequest, pk: int) -> HttpResponse:
    log_row = get_object_or_404(EPSSUpdateLog, pk=pk)
    _crumb(request, f"Log #{pk}")
    batches = EPSSDownloadBatch.objects.filter(log=log_row)
    return render(request, "dojo_epss/log_detail.html", {
        "log": log_row,
        "batches": batches,
    })


# ---------------------------------------------------------------------------
# 6) Manual Run page
# ---------------------------------------------------------------------------
# This view shows manual run actions. This view needs dashboard access.
@view_or_perm()
def manual_run(request: HttpRequest) -> HttpResponse:
    _crumb(request, "Manual Run")
    return render(request, "dojo_epss/manual_run.html", {
        "settings": EPSSSettings.load(),
    })


# ---------------------------------------------------------------------------
# Action endpoints
# ---------------------------------------------------------------------------
# This function starts a task. This function needs a Celery task or callable.
def _enqueue_or_run(task_fn, *args, **kwargs):
    """Run an EPSS task.

    Strategy:
      1. Try Celery's .delay() — async-queue path. Works on prod when the
         broker is reachable and the worker is consuming our task names.
      2. If that raises (broker outage, task not registered, etc.) fall
         back to .apply() — Celery's eager / synchronous run.
      3. If the task object has neither .delay nor .apply, call it directly.

    Either path writes an EPSSUpdateLog row inside the task itself, so the
    user sees the outcome on /epss/logs/ regardless of which path ran. The
    fallback also means the Manual Run buttons keep working on installs
    where the Celery worker has misconfigured task discovery.
    """
    # Step 1: try async
    if hasattr(task_fn, "delay"):
        try:
            return task_fn.delay(*args, **kwargs)
        except Exception as exc:
            log.warning("Celery .delay() failed: %s — falling back to inline run.", exc)

    # Step 2: synchronous run via Celery's eager mode
    if hasattr(task_fn, "apply"):
        try:
            result = task_fn.apply(args=args, kwargs=kwargs)
            if getattr(result, "failed", lambda: False)():
                log.error("Task failed in eager mode: %s", getattr(result, "traceback", ""))
            return result
        except Exception as exc:
            log.warning(".apply() failed: %s — falling back to direct call.", exc)

    # Step 3: bare function call (for tests / non-Celery environments)
    return task_fn(*args, **kwargs)


# This function catches action errors. This function needs an action label and redirect.
def _safe_action(label: str, redirect_to: str, view_fn):
    """Wrap an action so a runtime error never returns a bare 500 page —
    instead log the traceback and flash a clear error message before
    redirecting back to the relevant page.
    """
    @wraps(view_fn)
    def wrapper(request, *args, **kwargs):
        try:
            return view_fn(request, *args, **kwargs)
        except Exception as exc:  # pylint: disable=broad-except
            log.exception("Manual action %r failed", label)
            messages.error(
                request,
                f"{label} failed: {exc!s}. See server logs and /epss/logs/ for details.",
            )
            return HttpResponseRedirect(reverse(redirect_to))
    return wrapper


# This action starts FIRST.org fetch. This action needs a superuser POST.
@require_POST
@superuser_required
def action_firstorg_fetch(request: HttpRequest) -> HttpResponse:
    """Finding-driven fetch. Walks DefectDojo Findings, extracts CVEs,
    queries FIRST.org for those exact CVEs. Replaces the old
    'Fetch recent' / 'Fetch by threshold' buttons.
    """
    return _safe_action("FIRST.org fetch", "dojo_epss:logs", _do_firstorg_fetch)(request)


# This function runs FIRST.org fetch checks. This function needs FIRST.org source enabled.
def _do_firstorg_fetch(request: HttpRequest) -> HttpResponse:
    s = EPSSSettings.load()
    if s.active_fetch_source() != "firstorg":
        messages.warning(
            request,
            "FIRST.org fetch is disabled in EPSS Settings. Select "
            "'Fetch and compare from FIRST.org' before triggering this action.",
        )
        return HttpResponseRedirect(reverse("dojo_epss:manual_run"))
    _enqueue_or_run(epss_tasks.epss_fetch_findings_task, user_id=request.user.id)
    messages.info(
        request,
        "Fetch and compare from FIRST.org triggered. Eligible finding updates "
        "remain a separate action.",
    )
    return HttpResponseRedirect(reverse("dojo_epss:logs"))


# This action starts CSV download. This action needs a superuser POST.
@require_POST
@superuser_required
def action_download_csv(request: HttpRequest) -> HttpResponse:
    return _safe_action("CSV download", "dojo_epss:logs", _do_download_csv)(request)


# This function runs CSV download checks. This function needs CSV source enabled.
def _do_download_csv(request: HttpRequest) -> HttpResponse:
    # Server-side guard. The /epss/manual/ page only renders this button when
    # CSV mode is selected, but a hand-crafted POST should not bypass settings.
    s = EPSSSettings.load()
    if s.active_fetch_source() != "csv":
        messages.warning(
            request,
            "CSV download is disabled in EPSS Settings. Select "
            "'Download CSV and compare' before triggering this action.",
        )
        return HttpResponseRedirect(reverse("dojo_epss:manual_run"))

    date = (request.POST.get("score_date") or "").strip() or None
    if date:
        try:
            _dt.date.fromisoformat(date)
        except ValueError:
            messages.error(request, "Invalid date; expected YYYY-MM-DD.")
            return HttpResponseRedirect(reverse("dojo_epss:manual_run"))
    _enqueue_or_run(epss_tasks.epss_download_csv_task, date, user_id=request.user.id)
    messages.info(
        request,
        f"CSV download and compare triggered "
        f"({'date=' + date if date else 'always-current snapshot'}). "
        "Eligible finding updates remain a separate action.",
    )
    return HttpResponseRedirect(reverse("dojo_epss:logs"))


# This action starts EPSS comparison. This action needs a superuser POST.
@require_POST
@superuser_required
def action_compare(request: HttpRequest) -> HttpResponse:
    return _safe_action("Comparison", "dojo_epss:logs", _do_compare)(request)


# This function runs EPSS comparison. This function needs saved EPSS records.
def _do_compare(request: HttpRequest) -> HttpResponse:
    _enqueue_or_run(epss_tasks.epss_compare_findings_task, user_id=request.user.id)
    messages.info(request, "Comparison triggered.")
    return HttpResponseRedirect(reverse("dojo_epss:logs"))


# This action starts eligible finding updates. This action needs a superuser POST.
@require_POST
@superuser_required
def action_auto_update(request: HttpRequest) -> HttpResponse:
    return _safe_action("Auto-update", "dojo_epss:logs", _do_auto_update)(request)


# This function runs eligible finding updates. This function needs matched findings.
def _do_auto_update(request: HttpRequest) -> HttpResponse:
    dry_run = request.POST.get("dry_run") == "1"
    _enqueue_or_run(epss_tasks.epss_auto_update_findings_task, dry_run, user_id=request.user.id)
    messages.info(request, "Eligible finding update triggered.")
    return HttpResponseRedirect(reverse("dojo_epss:logs"))


# This action starts KEV sync. This action needs a superuser POST.
@require_POST
@superuser_required
def action_kev_sync(request: HttpRequest) -> HttpResponse:
    return _safe_action("KEV sync", "dojo_epss:logs", _do_kev_sync)(request)


# This function runs KEV sync checks. This function needs KEV updates enabled.
def _do_kev_sync(request: HttpRequest) -> HttpResponse:
    s = EPSSSettings.load()
    if not s.kev_enabled:
        messages.warning(request, "KEV checks are disabled in EPSS Settings.")
        return HttpResponseRedirect(reverse("dojo_epss:manual_run"))
    if not s.kev_update_findings_enabled:
        messages.warning(request, "KEV Finding updates are disabled in EPSS Settings.")
        return HttpResponseRedirect(reverse("dojo_epss:manual_run"))

    _enqueue_or_run(epss_tasks.kev_full_sync_task, user_id=request.user.id)
    source_label = "CSV" if s.kev_source_type == "csv" else "JSON/API"
    messages.info(
        request,
        f"KEV {source_label} sync triggered. Findings are updated positively only; "
        "existing KEV/ransomware Yes values and KEV dates are not reset.",
    )
    return HttpResponseRedirect(reverse("dojo_epss:logs"))


# This action tests FIRST.org connectivity. This action needs a superuser POST.
@require_POST
@superuser_required
def action_test_connection(request: HttpRequest) -> HttpResponse:
    ok, msg = FirstEPSSClient.from_settings().test_connection()
    (messages.success if ok else messages.error)(request, msg)
    return HttpResponseRedirect(reverse("dojo_epss:manual_run"))


# action_compare_one_cve / action_refetch_one_cve removed — they were tied
# to the CVE catalog UI that this library no longer exposes. The
# finding-driven flow makes single-CVE actions unnecessary: clicking
# "FIRST.org fetch" + "Compare" already covers every CVE present in
# Findings in one shot.


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
# _floatp helper removed — its only caller (the CVE catalog view) was deleted.
