"""Tests for the CVE extractor."""

from __future__ import annotations

import pytest

from dojo_epss.services.cve_extractor import (
    CVE_RE,
    extract_cves,
    extract_cves_with_origins,
)


def test_regex_only_matches_strict_cve_format():
    assert CVE_RE.search("CVE-2024-12345") is not None
    assert CVE_RE.search("CVE-1999-0001") is not None
    # Too few sequence digits.
    assert CVE_RE.search("CVE-2024-123") is None
    # Wrong prefix.
    assert CVE_RE.search("GHSA-2024-12345") is None


@pytest.mark.django_db
def test_extract_finds_cves_in_multiple_fields(fake_finding):
    fake_finding.description = "Affected by CVE-2024-99999 and reported via cve-2023-1111111."
    fake_finding.references = "Also see CVE-2022-0001"
    fake_finding.save()

    cves = extract_cves(fake_finding)
    # Includes Vulnerability_Id (CVE-2024-0002), Finding.cve (CVE-2024-0001),
    # description (CVE-2024-99999, CVE-2023-1111111), references (CVE-2022-0001).
    assert "CVE-2024-0001" in cves
    assert "CVE-2024-0002" in cves
    assert "CVE-2024-99999" in cves
    assert "CVE-2023-1111111" in cves
    assert "CVE-2022-0001" in cves


@pytest.mark.django_db
def test_extract_normalizes_to_uppercase_and_dedups(fake_finding):
    fake_finding.description = "lowercase cve-2024-0001 mentioned twice cve-2024-0001."
    fake_finding.save()
    cves = extract_cves(fake_finding)
    assert cves == sorted(set(cves))
    assert all(c == c.upper() for c in cves)


@pytest.mark.django_db
def test_extract_with_origins_records_field_names(fake_finding):
    fake_finding.description = "see CVE-2024-99999"
    fake_finding.save()
    origins = extract_cves_with_origins(fake_finding)
    assert "CVE-2024-0002" in origins  # Vulnerability_Id row
    assert "vulnerability_id" in origins["CVE-2024-0002"]
    assert "description" in origins["CVE-2024-99999"]


@pytest.mark.django_db
def test_extract_handles_missing_fields_gracefully(fake_finding):
    # Strip everything optional.
    fake_finding.cve = ""
    fake_finding.description = ""
    fake_finding.references = ""
    fake_finding.save()
    fake_finding.vulnerability_id_set.all().delete()
    assert extract_cves(fake_finding) == []
