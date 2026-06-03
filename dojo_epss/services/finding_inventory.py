"""Finding CVE inventory helpers."""

from __future__ import annotations

from dataclasses import dataclass

from ..queries import get_finding_model
from .cve_extractor import extract_cves_with_origins


@dataclass
class FindingCVEInventory:
    scanned_count: int
    with_cves: list[tuple[object, list[str]]]
    all_cves: set[str]


# This function collects Finding CVEs. This function needs the Finding model.
def collect_finding_cves(extra_fields: list[str] | None = None) -> FindingCVEInventory:
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
        *(extra_fields or []),
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
    return FindingCVEInventory(scanned_count, with_cves, all_cves)


# This function keeps valid Finding fields. This function needs field names.
def _safe_field_names(names: list[str]) -> list[str]:
    Finding = get_finding_model()
    out = []
    for name in names:
        try:
            Finding._meta.get_field(name)
            out.append(name)
        except Exception:
            continue
    return list(dict.fromkeys(out))


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
