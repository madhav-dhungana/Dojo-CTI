"""Tests for CTI DB sync behavior."""

from __future__ import annotations

import datetime as _dt
import gzip
import io
import json

import pytest
import responses

from dojo_epss.models import CTICVERecord, KEVSourceType
from dojo_epss.services.cti_db_updater import sync_cti_db


def _gz_csv(score_date, rows):
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(
            f"#model_version:v2024.05.01,score_date:{score_date.isoformat()}T00:00:00+0000\n".encode(),
        )
        gz.write(b"cve,epss,percentile\n")
        for cve, epss, pct in rows:
            gz.write(f"{cve},{epss},{pct}\n".encode())
    return buf.getvalue()


def _enable_cti(settings_row):
    settings_row.enabled = True
    settings_row.cti_db_enabled = True
    settings_row.cti_db_sync_vulncheck_enabled = False
    settings_row.kev_source_type = KEVSourceType.JSON
    settings_row.kev_source_url = "https://example.test/kev.json"
    settings_row.save()


@responses.activate
@pytest.mark.django_db
def test_cti_db_sync_uses_csv_force_and_full_kev_feed(settings_row):
    _enable_cti(settings_row)
    settings_row.download_full_csv_enabled = False
    settings_row.cti_db_sync_epss_enabled = True
    settings_row.cti_db_sync_kev_enabled = True
    settings_row.save()

    score_date = _dt.date(2026, 5, 20)
    responses.add(
        responses.GET,
        settings_row.csv_url_for(None),
        body=_gz_csv(score_date, [("CVE-2024-0001", "0.5", "0.6")]),
        status=200,
        content_type="application/octet-stream",
    )
    responses.add(
        responses.GET,
        settings_row.kev_source_url,
        body=json.dumps({
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-0001",
                    "dateAdded": "2026-05-21",
                    "knownRansomwareCampaignUse": "Known",
                },
                {
                    "cveID": "CVE-2024-9999",
                    "dateAdded": "2026-05-22",
                    "knownRansomwareCampaignUse": "Unknown",
                },
            ],
        }),
        status=200,
        content_type="application/json",
    )

    stats = sync_cti_db(settings=settings_row)

    assert stats["epss"]["saved"] == 1
    assert stats["kev"]["saved"] == 2
    assert CTICVERecord.objects.count() == 2
    epss_row = CTICVERecord.objects.get(cve_id="CVE-2024-0001")
    kev_only_row = CTICVERecord.objects.get(cve_id="CVE-2024-9999")
    assert epss_row.epss_date == score_date
    assert epss_row.known_exploited is True
    assert epss_row.ransomware_used is True
    assert kev_only_row.known_exploited is True
    assert kev_only_row.ransomware_used is False


@responses.activate
@pytest.mark.django_db
def test_cti_db_sync_preserves_existing_first_found_dates(settings_row):
    _enable_cti(settings_row)
    settings_row.cti_db_sync_epss_enabled = False
    settings_row.cti_db_sync_kev_enabled = True
    settings_row.save()

    first_found = _dt.date(2026, 1, 10)
    CTICVERecord.objects.create(
        cve_id="CVE-2024-0001",
        known_exploited=True,
        ransomware_used=True,
        kev_found_date=first_found,
        ransomware_found_date=first_found,
    )
    responses.add(
        responses.GET,
        settings_row.kev_source_url,
        body=json.dumps({
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-0001",
                    "dateAdded": "2026-05-21",
                    "knownRansomwareCampaignUse": "Known",
                },
            ],
        }),
        status=200,
        content_type="application/json",
    )

    sync_cti_db(settings=settings_row)

    row = CTICVERecord.objects.get(cve_id="CVE-2024-0001")
    assert row.kev_found_date == first_found
    assert row.ransomware_found_date == first_found
    assert row.kev_date_added == _dt.date(2026, 5, 21)
