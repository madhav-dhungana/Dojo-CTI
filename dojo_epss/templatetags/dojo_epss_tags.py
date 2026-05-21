"""Template tags used to render the 'EPSS Update' column on the Findings list.

Patch DefectDojo's ``dojo/templates/dojo/findings_list_snippet.html`` with
two short additions (header cell + body cell). See README.md for the exact
diff.
"""

from __future__ import annotations

from django import template
from django.urls import NoReverseMatch, reverse

from ..models import FindingEPSSUpdate

register = template.Library()


# ---------------------------------------------------------------------------
# Per-row tag (one query per call)
# ---------------------------------------------------------------------------
@register.inclusion_tag("dojo_epss/partials/finding_epss_update_column.html")
def epss_update_for(finding):
    fu = (
        FindingEPSSUpdate.objects
        .select_related("source_record")
        .filter(finding_id=getattr(finding, "id", None))
        .first()
    )
    return {"fu": fu, "log_url": _log_url_for(fu)}


# ---------------------------------------------------------------------------
# Bulk-preload tag (one query per page)
# ---------------------------------------------------------------------------
@register.simple_tag(takes_context=True)
def epss_update_preload(context, findings):
    ids = [getattr(f, "id", None) for f in findings if getattr(f, "id", None)]
    if not ids:
        context["epss_updates_by_finding"] = {}
        return ""
    context["epss_updates_by_finding"] = {
        fu.finding_id: fu
        for fu in FindingEPSSUpdate.objects.select_related("source_record").filter(finding_id__in=ids)
    }
    return ""


@register.inclusion_tag(
    "dojo_epss/partials/finding_epss_update_column.html",
    takes_context=True,
)
def epss_update_for_preloaded(context, finding):
    bucket = context.get("epss_updates_by_finding") or {}
    fu = bucket.get(getattr(finding, "id", None))
    return {"fu": fu, "log_url": _log_url_for(fu)}


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------
def _log_url_for(fu) -> str | None:
    """Link from a Findings-list cell to relevant EPSS context.

    Catalog detail pages were removed (this library is finding-driven), so
    we point at /epss/finding-matches/ filtered by the finding — if that
    URL exists — and fall back to /epss/logs/.
    """
    if fu is None:
        return None
    try:
        return reverse("dojo_epss:finding_matches")
    except NoReverseMatch:
        try:
            return reverse("dojo_epss:logs")
        except NoReverseMatch:
            return None
