"""Tests for positive-only VulnCheck Finding updates."""

from __future__ import annotations

import datetime as _dt

import pytest

from dojo_epss.models import FindingVulnCheckUpdate
from dojo_epss.services import vulncheck_updater
from dojo_epss.services.vulncheck_client import VulnCheckFetchResult, VulnCheckRow


def _row(cve_id, *, poc=True, itw=True, poc_date=None, itw_date=None):
    return VulnCheckRow(
        cve_id=cve_id,
        public_exploit_found=poc,
        exploit_in_the_wild=itw,
        commercial_exploit_found=False,
        weaponized_exploit_found=itw,
        reported_exploited_by_threat_actors=False,
        reported_exploited_by_ransomware=False,
        reported_exploited_by_botnets=False,
        reported_exploited_by_honeypot_service=False,
        reported_exploited_by_vulncheck_canaries=False,
        in_cisa_kev=False,
        in_vulncheck_kev=False,
        max_exploit_maturity="weaponized" if itw else "poc",
        poc_found_date=poc_date,
        itw_found_date=itw_date,
        exploit_count=1,
        source_index="exploits",
        source_links=[{"url": "https://example.test/poc"}],
        raw_data={"id": cve_id},
    )


class _FakeClient:
    def __init__(self, settings, token):  # noqa: D107, ARG002
        pass

    def fetch_cves(self, cves):
        rows = {
            "CVE-2024-0001": _row(
                "CVE-2024-0001",
                poc_date=_dt.date(2026, 1, 2),
                itw_date=_dt.date(2026, 2, 3),
            ),
        }
        return VulnCheckFetchResult(
            rows_by_cve=rows,
            cves_checked=len(set(cves)),
            api_records_seen=1,
            requests_made=1,
            source_index="exploits",
            available_indexes=["exploits"],
        )


@pytest.mark.django_db
def test_vulncheck_sync_creates_positive_snapshot(monkeypatch, fake_finding, settings_row):
    settings_row.vulncheck_enabled = True
    settings_row.vulncheck_api_token_encrypted = "encrypted"
    settings_row.save()
    monkeypatch.setattr(settings_row, "get_vulncheck_api_token", lambda: "token")
    monkeypatch.setattr(vulncheck_updater, "VulnCheckClient", _FakeClient)

    stats = vulncheck_updater.sync_vulncheck_findings(settings=settings_row)

    assert stats["unique_cves"] == 2
    assert stats["matched_cves"] == 1
    assert stats["matched_findings"] == 1
    assert stats["updated_findings"] == 1

    fu = FindingVulnCheckUpdate.objects.get(finding=fake_finding)
    assert fu.public_exploit_found is True
    assert fu.exploit_in_the_wild is True
    assert fu.poc_found_date == _dt.date(2026, 1, 2)
    assert fu.itw_found_date == _dt.date(2026, 2, 3)


@pytest.mark.django_db
def test_vulncheck_sync_does_not_overwrite_existing_found_dates(monkeypatch, fake_finding, settings_row):
    settings_row.vulncheck_enabled = True
    settings_row.vulncheck_api_token_encrypted = "encrypted"
    settings_row.save()
    original_poc = _dt.date(2025, 3, 4)
    original_itw = _dt.date(2025, 4, 5)
    FindingVulnCheckUpdate.objects.create(
        finding=fake_finding,
        cve_id="CVE-2024-0001",
        public_exploit_found=True,
        exploit_in_the_wild=True,
        poc_found_date=original_poc,
        itw_found_date=original_itw,
    )
    monkeypatch.setattr(settings_row, "get_vulncheck_api_token", lambda: "token")
    monkeypatch.setattr(vulncheck_updater, "VulnCheckClient", _FakeClient)

    vulncheck_updater.sync_vulncheck_findings(settings=settings_row)

    fu = FindingVulnCheckUpdate.objects.get(finding=fake_finding)
    assert fu.poc_found_date == original_poc
    assert fu.itw_found_date == original_itw
