"""Tests for KEV source parsing."""

from __future__ import annotations

import json

import pytest
import responses

from dojo_epss.models import KEVSourceType
from dojo_epss.services.kev_source import fetch_matching_kev_rows


@responses.activate
@pytest.mark.django_db
def test_json_source_filters_to_requested_cves(settings_row):
    settings_row.kev_source_type = KEVSourceType.JSON
    settings_row.kev_source_url = "https://example.test/kev.json"
    settings_row.save()

    responses.add(
        responses.GET,
        settings_row.kev_source_url,
        body=json.dumps({
            "catalogVersion": "2026.05.21",
            "dateReleased": "2026-05-21T00:00:00Z",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-0001",
                    "dateAdded": "2026-05-21",
                    "knownRansomwareCampaignUse": "Known",
                },
                {
                    "cveID": "CVE-2024-9999",
                    "dateAdded": "2026-05-21",
                    "knownRansomwareCampaignUse": "Unknown",
                },
            ],
        }),
        status=200,
        content_type="application/json",
    )

    result = fetch_matching_kev_rows(["CVE-2024-0001"], settings=settings_row)
    assert result.total_rows_seen == 2
    assert result.catalog_version == "2026.05.21"
    assert sorted(result.rows_by_cve) == ["CVE-2024-0001"]
    assert result.rows_by_cve["CVE-2024-0001"].ransomware_used is True


@responses.activate
@pytest.mark.django_db
def test_csv_source_filters_to_requested_cves(settings_row):
    settings_row.kev_source_type = KEVSourceType.CSV
    settings_row.kev_source_url = "https://example.test/kev.csv"
    settings_row.save()

    responses.add(
        responses.GET,
        settings_row.kev_source_url,
        body=(
            "cveID,dateAdded,knownRansomwareCampaignUse\n"
            "CVE-2024-0001,2026-05-21,Unknown\n"
            "CVE-2024-0002,2026-05-21,Known\n"
        ),
        status=200,
        content_type="text/csv",
    )

    result = fetch_matching_kev_rows(["CVE-2024-0002"], settings=settings_row)
    assert result.total_rows_seen == 2
    assert sorted(result.rows_by_cve) == ["CVE-2024-0002"]
    assert result.rows_by_cve["CVE-2024-0002"].ransomware_used is True
