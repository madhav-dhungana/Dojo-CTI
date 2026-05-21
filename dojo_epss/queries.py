"""Centralized DB queries for dojo_epss.

All ``dojo`` model lookups go through ``apps.get_model`` so this app loads
even when ``dojo`` isn't importable yet (e.g. during initial migrations or
in test environments without the full dojo dependency tree).
"""

from __future__ import annotations

from typing import Iterable

from django.apps import apps
from django.db.models import Q

from . import app_settings


# This function loads the Finding model. This function needs the Dojo app label.
def get_finding_model():
    return apps.get_model(app_settings.dojo_app_label(), "Finding")


# This function loads the Vulnerability_Id model. This function needs the Dojo app label.
def get_vulnerability_id_model():
    try:
        return apps.get_model(app_settings.dojo_app_label(), "Vulnerability_Id")
    except LookupError:
        return None


# This function finds Findings for CVEs. This function needs CVE ids.
def find_findings_for_cves(cves: Iterable[str]):
    """Finding queryset for any Finding matching any of ``cves`` via the
    legacy ``cve`` field OR the Vulnerability_Id reverse relation.
    """
    cves = sorted({c.strip().upper() for c in cves if c and c.strip()})
    Finding = get_finding_model()
    if not cves:
        return Finding.objects.none()

    VulnId = get_vulnerability_id_model()
    q = Q()
    if _model_has_field(Finding, "cve"):
        q |= Q(cve__in=cves)
    if VulnId is not None and _model_has_field(VulnId, "vulnerability_id"):
        related = _reverse_relation_name(Finding, VulnId) or "vulnerability_id_set"
        q |= Q(**{f"{related}__vulnerability_id__in": cves})
    return Finding.objects.filter(q).distinct()


# This function maps CVEs to Finding ids. This function needs CVE ids.
def cve_existence_map(cves: Iterable[str]) -> dict[str, list[int]]:
    """``{cve: [finding_id, ...]}`` for the given CVEs (req #3, #4)."""
    cves = sorted({c.strip().upper() for c in cves if c and c.strip()})
    out: dict[str, list[int]] = {c: [] for c in cves}
    if not cves:
        return out

    Finding = get_finding_model()
    VulnId = get_vulnerability_id_model()

    if _model_has_field(Finding, "cve"):
        for cve_val, fid in Finding.objects.filter(cve__in=cves).values_list("cve", "id"):
            if cve_val:
                out.setdefault(cve_val.upper(), []).append(fid)

    if VulnId is not None and _model_has_field(VulnId, "vulnerability_id"):
        finding_fk = _fk_field_name(VulnId, Finding) or "finding"
        for vid, fid in VulnId.objects.filter(vulnerability_id__in=cves).values_list(
            "vulnerability_id", f"{finding_fk}_id",
        ):
            if vid and fid:
                out.setdefault(vid.upper(), []).append(fid)

    return {cve: sorted(set(ids)) for cve, ids in out.items()}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
# This function checks if a model has a field. This function needs a model and field name.
def _model_has_field(model, name: str) -> bool:
    try:
        model._meta.get_field(name)
        return True
    except Exception:
        return False


# This function finds a reverse relation. This function needs parent and child models.
def _reverse_relation_name(parent_model, child_model) -> str | None:
    for rel in parent_model._meta.get_fields():
        try:
            if getattr(rel, "related_model", None) is child_model and rel.auto_created:
                return rel.get_accessor_name()
        except Exception:
            continue
    return None


# This function finds a foreign key field. This function needs child and parent models.
def _fk_field_name(child_model, parent_model) -> str | None:
    for f in child_model._meta.get_fields():
        if getattr(f, "many_to_one", False) and getattr(f, "related_model", None) is parent_model:
            return f.name
    return None
