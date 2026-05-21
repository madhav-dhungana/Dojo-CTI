"""CVE extractor.

Inspects a DefectDojo Finding and returns the set of CVE IDs found across
**all** plausible fields. Verified against DefectDojo 2.58.2 inspection:

  * ``Finding.cve``                 — CharField(max=50). May hold a CVE OR
                                      another vulnerability identifier; we
                                      validate with strict regex.
  * ``Vulnerability_Id`` related FK — separate model; multiple per Finding.
                                      ``Finding.vulnerability_id_set`` is the
                                      reverse accessor.
  * ``Finding.title``               — CharField(max=511).
  * ``Finding.description``         — TextField (deduplication-deferred).
  * ``Finding.references``          — TextField.
  * ``Finding.mitigation``          — TextField.
  * ``Finding.impact``              — TextField.
  * ``Finding.steps_to_reproduce``  — TextField.
  * ``Finding.component_name``,
    ``Finding.component_version``   — CharFields (rarely contain CVEs but
                                      cheap to scan).

We use ``getattr(..., "", default)`` for every read so this code keeps
working if a downstream fork drops or renames a field.

Output is uppercase, deduplicated, and sorted (deterministic).
"""

from __future__ import annotations

import re
from typing import Iterable, Sequence

# Strict CVE regex: 4-digit year, then ≥4 sequence digits.
CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,})\b", re.IGNORECASE)


# Order matters: iterating in this order means the first occurrence wins
# when the matcher records "where each CVE came from" in details.
_TEXT_FIELDS: Sequence[str] = (
    "cve",
    "title",
    "description",
    "references",
    "mitigation",
    "impact",
    "steps_to_reproduce",
    "component_name",
    "component_version",
)


# This function extracts CVE ids. This function needs a Finding.
def extract_cves(finding) -> list[str]:
    """Return a sorted, deduplicated, upper-cased list of CVE ids.

    Never raises: missing fields are skipped silently.
    """
    found: set[str] = set()

    # 1. Vulnerability_Id related rows (DefectDojo's preferred multi-ID source).
    found.update(_iter_vulnerability_ids(finding))

    # 2. Plain text fields on the Finding itself.
    for fname in _TEXT_FIELDS:
        value = getattr(finding, fname, None)
        if not value:
            continue
        for match in CVE_RE.finditer(str(value)):
            found.add(_normalize(match))

    return sorted(found)


# This function extracts CVEs with field names. This function needs a Finding.
def extract_cves_with_origins(finding) -> dict[str, list[str]]:
    """Like extract_cves, but returns ``{cve: [field_name, ...]}``.

    Used by the matcher to populate ``EPSSUpdateLog.details`` for forensic
    visibility. A CVE found in both ``vulnerability_id`` and ``description``
    will list both field names.
    """
    origins: dict[str, list[str]] = {}

    for cve in _iter_vulnerability_ids(finding):
        origins.setdefault(cve, []).append("vulnerability_id")

    for fname in _TEXT_FIELDS:
        value = getattr(finding, fname, None)
        if not value:
            continue
        for match in CVE_RE.finditer(str(value)):
            cve = _normalize(match)
            origins.setdefault(cve, []).append(fname)

    # Dedup origin lists while preserving first-seen order.
    return {
        cve: list(dict.fromkeys(srcs))
        for cve, srcs in sorted(origins.items())
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
# This function reads related vulnerability ids. This function needs a Finding.
def _iter_vulnerability_ids(finding) -> Iterable[str]:
    """Yield uppercase CVE ids from the Vulnerability_Id related model.

    Tries the documented related_name first, then falls back to common
    Django reverse-accessor patterns.
    """
    for accessor in ("vulnerability_id_set", "vulnerability_ids"):
        manager = getattr(finding, accessor, None)
        if manager is None:
            continue
        try:
            for vid_obj in manager.all():
                vid = getattr(vid_obj, "vulnerability_id", None)
                if not vid:
                    continue
                m = CVE_RE.search(str(vid))
                if m:
                    yield _normalize(m)
        except Exception:  # pragma: no cover - non-existent reverse manager
            continue
        return  # use the first accessor that worked


# This function formats a regex match as CVE. This function needs a match.
def _normalize(match: re.Match) -> str:
    return f"CVE-{match.group(1)}-{match.group(2)}".upper()
