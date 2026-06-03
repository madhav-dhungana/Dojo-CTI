"""Tests for VulnCheck response parsing."""

from __future__ import annotations

import datetime as _dt

from dojo_epss.services.vulncheck_client import _row_from_record


def test_vulncheck_row_extracts_poc_and_itw_signals():
    row = _row_from_record({
        "id": "CVE-2024-0001",
        "public_exploit_found": True,
        "weaponized_exploit_found": True,
        "reported_exploited": True,
        "reported_exploited_by_ransomware": True,
        "inKEV": True,
        "max_exploit_maturity": "weaponized",
        "timeline": {
            "first_exploit_published": "2026-01-02T03:04:05Z",
            "first_reported_ransomware": "2026-02-03T00:00:00Z",
        },
        "counts": {"exploits": 4},
        "exploits": [{
            "url": "https://example.test/poc",
            "name": "example poc",
            "exploit_maturity": "poc",
            "date_added": "2026-01-02",
        }],
    }, "exploits")

    assert row is not None
    assert row.cve_id == "CVE-2024-0001"
    assert row.public_exploit_found is True
    assert row.exploit_in_the_wild is True
    assert row.weaponized_exploit_found is True
    assert row.reported_exploited_by_ransomware is True
    assert row.in_cisa_kev is True
    assert row.poc_found_date == _dt.date(2026, 1, 2)
    assert row.itw_found_date == _dt.date(2026, 2, 3)
    assert row.exploit_count == 4
    assert row.source_links[0]["url"] == "https://example.test/poc"
