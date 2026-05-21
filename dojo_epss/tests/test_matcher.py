"""Tests for the matcher + updater services."""

from __future__ import annotations

import datetime as _dt
from decimal import Decimal

import pytest

from dojo_epss.models import (
    EPSSCVERecord,
    EPSSStatus,
    EPSSSettings,
    EPSSUpdateLog,
    FindingEPSSUpdate,
)
from dojo_epss.services.finding_matcher import compare
from dojo_epss.services.finding_updater import auto_update


def _record(cve, epss="0.5", pct="0.6", date=None):
    return EPSSCVERecord.objects.create(
        cve_id=cve,
        epss_score=Decimal(epss),
        epss_percentile=Decimal(pct),
        epss_date=date or _dt.date(2024, 5, 1),
    )


@pytest.mark.django_db
def test_compare_skips_when_disabled(fake_finding, settings_row):
    _record("CVE-2024-0001")
    settings_row.compare_against_findings_enabled = False
    settings_row.save()
    stats = compare(settings=settings_row)
    assert stats["matched"] == 0
    assert FindingEPSSUpdate.objects.count() == 0


@pytest.mark.django_db
def test_compare_creates_one_update_per_finding(fake_finding):
    # Two CVEs map to the same Finding (one via cve, one via Vulnerability_Id).
    r1 = _record("CVE-2024-0001", epss="0.30")
    r2 = _record("CVE-2024-0002", epss="0.80")
    stats = compare()
    assert stats["matched"] == 1
    fu = FindingEPSSUpdate.objects.get(finding=fake_finding)
    # Highest EPSS wins (0.80 from CVE-2024-0002).
    assert fu.cve_id == "CVE-2024-0002"
    assert fu.source_record == r2
    assert fu.status == EPSSStatus.MATCHED


@pytest.mark.django_db
def test_compare_records_all_cves_in_log_details(fake_finding):
    _record("CVE-2024-0001", epss="0.30")
    _record("CVE-2024-0002", epss="0.80")
    log = EPSSUpdateLog.objects.create(action="compare")
    compare(update_log=log)
    log.refresh_from_db()
    detail_map = log.details.get("matched_finding_cves", {})
    assert str(fake_finding.id) in detail_map
    assert set(detail_map[str(fake_finding.id)]) >= {"CVE-2024-0001", "CVE-2024-0002"}


@pytest.mark.django_db
def test_auto_update_skipped_when_disabled(fake_finding, settings_row):
    _record("CVE-2024-0001", epss="0.5")
    compare()
    stats = auto_update(settings=settings_row)
    assert stats["updated"] == 0


@pytest.mark.django_db
def test_auto_update_writes_finding_fields_when_enabled(fake_finding, settings_row):
    _record("CVE-2024-0002", epss="0.85", pct="0.95")
    compare()
    settings_row.auto_update_enabled = True
    settings_row.save()
    stats = auto_update(settings=settings_row)
    assert stats["updated"] == 1
    fake_finding.refresh_from_db()
    assert fake_finding.epss_score == pytest.approx(0.85)
    assert fake_finding.epss_percentile == pytest.approx(0.95)


@pytest.mark.django_db
def test_auto_update_skips_inactive_when_active_only(fake_finding, settings_row):
    fake_finding.active = False
    fake_finding.save()
    _record("CVE-2024-0002", epss="0.85")
    compare()
    settings_row.auto_update_enabled = True
    settings_row.update_active_findings_only = True
    settings_row.save()
    stats = auto_update(settings=settings_row)
    assert stats["updated"] == 0
    assert stats["skipped"] == 1


@pytest.mark.django_db
def test_auto_update_dry_run_writes_nothing(fake_finding, settings_row):
    _record("CVE-2024-0002", epss="0.85", pct="0.95")
    compare()
    settings_row.auto_update_enabled = True
    settings_row.save()
    stats = auto_update(settings=settings_row, dry_run=True)
    assert stats["updated"] == 1  # decision was "update"
    fake_finding.refresh_from_db()
    # But the actual write didn't happen.
    assert fake_finding.epss_score is None


@pytest.mark.django_db
def test_auto_update_skips_when_severity_filter_excludes(fake_finding, settings_row):
    fake_finding.severity = "Low"
    fake_finding.save()
    _record("CVE-2024-0002", epss="0.85")
    compare()
    settings_row.auto_update_enabled = True
    settings_row.update_severities = ["Critical"]
    settings_row.save()
    stats = auto_update(settings=settings_row)
    assert stats["updated"] == 0
    assert stats["skipped"] == 1


@pytest.mark.django_db
def test_auto_update_reconsiders_skipped_rows_when_scope_changes(fake_finding, settings_row):
    fake_finding.severity = "Low"
    fake_finding.save()
    _record("CVE-2024-0002", epss="0.85", pct="0.95")
    compare()

    settings_row.auto_update_enabled = True
    settings_row.update_severities = ["Critical"]
    settings_row.save()
    stats = auto_update(settings=settings_row)
    assert stats["updated"] == 0
    assert stats["skipped"] == 1

    settings_row.update_severities = []
    settings_row.save()
    stats = auto_update(settings=settings_row)
    assert stats["updated"] == 1
