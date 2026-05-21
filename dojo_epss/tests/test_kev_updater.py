"""Tests for positive-only KEV Finding updates."""

from __future__ import annotations

import datetime as _dt

import pytest
from django.utils import timezone

from dojo_epss.models import FindingKEVUpdate, KEVSourceType
from dojo_epss.services import kev_updater
from dojo_epss.services.kev_source import KevFetchResult, KevRow


def _kev_result(rows_by_cve):
    return KevFetchResult(
        rows_by_cve=rows_by_cve,
        total_rows_seen=len(rows_by_cve),
        catalog_version="test",
        date_released="",
        source_url="https://example.test/kev.json",
        source_type=KEVSourceType.JSON,
    )


@pytest.mark.django_db
def test_kev_sync_sets_positive_finding_fields(monkeypatch, fake_finding, settings_row):
    settings_row.kev_enabled = True
    settings_row.kev_update_findings_enabled = True
    settings_row.save()

    monkeypatch.setattr(
        kev_updater,
        "fetch_matching_kev_rows",
        lambda cves, settings: _kev_result({
            "CVE-2024-0001": KevRow(
                cve_id="CVE-2024-0001",
                ransomware_used=True,
                date_added=_dt.date(2026, 5, 21),
                raw_data={"cveID": "CVE-2024-0001"},
            ),
        }),
    )

    stats = kev_updater.sync_kev_findings(settings=settings_row)
    assert stats["matched_findings"] == 1
    assert stats["updated_findings"] == 1

    fake_finding.refresh_from_db()
    assert fake_finding.known_exploited is True
    assert fake_finding.ransomware_used is True
    assert fake_finding.kev_date == timezone.localdate()

    fu = FindingKEVUpdate.objects.get(finding=fake_finding)
    assert fu.known_exploited is True
    assert fu.ransomware_used is True
    assert fu.kev_found_date == fake_finding.kev_date
    assert fu.ransomware_found_date == fake_finding.kev_date


@pytest.mark.django_db
def test_kev_sync_does_not_overwrite_existing_found_date(monkeypatch, fake_finding, settings_row):
    settings_row.kev_enabled = True
    settings_row.kev_update_findings_enabled = True
    settings_row.save()

    original_date = _dt.date(2025, 1, 15)
    fake_finding.known_exploited = True
    fake_finding.kev_date = original_date
    fake_finding.save(update_fields=["known_exploited", "kev_date"])
    FindingKEVUpdate.objects.create(
        finding=fake_finding,
        cve_id="CVE-2024-0001",
        known_exploited=True,
        kev_found_date=original_date,
    )

    monkeypatch.setattr(
        kev_updater,
        "fetch_matching_kev_rows",
        lambda cves, settings: _kev_result({
            "CVE-2024-0001": KevRow(
                cve_id="CVE-2024-0001",
                ransomware_used=False,
                date_added=_dt.date(2026, 5, 21),
                raw_data={"cveID": "CVE-2024-0001"},
            ),
        }),
    )

    kev_updater.sync_kev_findings(settings=settings_row)

    fake_finding.refresh_from_db()
    fu = FindingKEVUpdate.objects.get(finding=fake_finding)
    assert fake_finding.kev_date == original_date
    assert fu.kev_found_date == original_date
