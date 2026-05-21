"""Sanity tests for the dojo_epss models."""

from __future__ import annotations

import datetime as _dt
from decimal import Decimal

import pytest

from dojo_epss.models import (
    EPSSCVERecord,
    EPSSDownloadBatch,
    EPSSLogStatus,
    EPSSSettings,
    EPSSStatus,
    EPSSUpdateLog,
    FindingEPSSUpdate,
)


@pytest.mark.django_db
def test_settings_singleton():
    a = EPSSSettings.load()
    b = EPSSSettings.load()
    assert a.pk == b.pk == EPSSSettings.SINGLETON_ID
    assert EPSSSettings.objects.count() == 1


@pytest.mark.django_db
def test_csv_url_uses_configurable_base():
    s = EPSSSettings.load()
    s.csv_base_url = "https://internal.example/epss"
    s.save()
    assert s.csv_url_for(_dt.date(2024, 5, 1)) == \
        "https://internal.example/epss/epss_scores-2024-05-01.csv.gz"


@pytest.mark.django_db
def test_csv_url_for_none_returns_current_pointer():
    """When no date is passed, csv_url_for should return the always-current
    pointer to avoid the 'today's file not published yet → 403' race."""
    s = EPSSSettings.load()
    s.csv_base_url = "https://internal.example/epss"
    s.save()
    assert s.csv_url_for() == \
        "https://internal.example/epss/epss_scores-current.csv.gz"
    assert s.csv_url_for(score_date=None) == \
        "https://internal.example/epss/epss_scores-current.csv.gz"


@pytest.mark.django_db
def test_record_unique_constraint_per_date_source():
    EPSSCVERecord.objects.create(
        cve_id="CVE-2024-0001", epss_score=Decimal("0.10"),
        epss_percentile=Decimal("0.20"),
        epss_date=_dt.date(2024, 5, 1),
    )
    with pytest.raises(Exception):
        EPSSCVERecord.objects.create(
            cve_id="CVE-2024-0001", epss_score=Decimal("0.50"),
            epss_percentile=Decimal("0.60"),
            epss_date=_dt.date(2024, 5, 1),
        )
    # Different source should be allowed.
    EPSSCVERecord.objects.create(
        cve_id="CVE-2024-0001", epss_score=Decimal("0.50"),
        epss_percentile=Decimal("0.60"),
        epss_date=_dt.date(2024, 5, 1),
        source="manual",
    )


@pytest.mark.django_db
def test_finding_epss_update_default_status(fake_finding):
    fu = FindingEPSSUpdate.objects.create(finding=fake_finding, cve_id="CVE-2024-0001")
    assert fu.status == EPSSStatus.NOT_CHECKED


@pytest.mark.django_db
def test_finding_epss_update_is_one_to_one(fake_finding):
    FindingEPSSUpdate.objects.create(finding=fake_finding)
    with pytest.raises(Exception):
        FindingEPSSUpdate.objects.create(finding=fake_finding)


@pytest.mark.django_db
def test_severities_list_parsing():
    s = EPSSSettings.load()
    s.update_severities = ["Critical", "High", " ", "Medium"]
    s.save()
    assert s.severities_list() == ["Critical", "High", "Medium"]


@pytest.mark.django_db
def test_product_id_list_parsing_handles_garbage():
    s = EPSSSettings.load()
    s.update_products = [1, "2", "x", 3, None]
    s.save()
    assert s.product_id_list() == [1, 2, 3]


@pytest.mark.django_db
def test_update_log_mark_finished():
    log = EPSSUpdateLog.objects.create(action="fetch_recent", status=EPSSLogStatus.STARTED)
    log.mark_finished(EPSSLogStatus.SUCCESS)
    log.refresh_from_db()
    assert log.status == EPSSLogStatus.SUCCESS
    assert log.finished_at is not None
