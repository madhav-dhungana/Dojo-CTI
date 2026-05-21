"""Tests for the FIRST.org REST client. Uses ``responses`` to stub HTTP."""

from __future__ import annotations

import datetime as _dt
from decimal import Decimal

import pytest
import responses

from dojo_epss.services.first_client import (
    EpssRow,
    FirstEPSSClient,
)
from dojo_epss.services.http import EpssFetchError


def _ok(rows, total=None, offset=0, limit=100):
    return {
        "status": "OK", "status-code": 200, "version": "1.0", "access": "public",
        "total": total if total is not None else len(rows),
        "offset": offset, "limit": limit, "data": rows,
    }


@responses.activate
def test_fetch_single_returns_row():
    responses.add(
        responses.GET, "https://api.first.org/data/v1/epss",
        json=_ok([{"cve": "CVE-2024-0001", "epss": "0.97",
                   "percentile": "0.99", "date": "2024-05-01"}]),
    )
    row = FirstEPSSClient().fetch_single("CVE-2024-0001")
    assert row is not None
    assert row.cve == "CVE-2024-0001"
    assert row.epss == Decimal("0.97")
    assert row.score_date == _dt.date(2024, 5, 1)


@responses.activate
def test_fetch_recent_with_limit():
    responses.add(
        responses.GET, "https://api.first.org/data/v1/epss",
        json=_ok([{"cve": f"CVE-2024-{i:04d}", "epss": "0.5",
                   "percentile": "0.6", "date": "2024-05-01"} for i in range(10)]),
    )
    rows = FirstEPSSClient().fetch_recent(limit=10)
    assert len(rows) == 10


@responses.activate
def test_fetch_by_threshold_paginates():
    base = "https://api.first.org/data/v1/epss"
    p1 = _ok([{"cve": f"CVE-2024-{i:04d}", "epss": "0.5",
               "percentile": "0.6", "date": "2024-05-01"} for i in range(100)],
             total=150, offset=0, limit=100)
    p2 = _ok([{"cve": f"CVE-2024-{i:04d}", "epss": "0.5",
               "percentile": "0.6", "date": "2024-05-01"} for i in range(100, 150)],
             total=150, offset=100, limit=100)
    responses.add(responses.GET, base, json=p1)
    responses.add(responses.GET, base, json=p2)
    rows = list(FirstEPSSClient().fetch_by_threshold(epss_gte=0.5, order_by_epss_desc=True))
    assert len(rows) == 150


@responses.activate
def test_4xx_does_not_retry():
    responses.add(
        responses.GET, "https://api.first.org/data/v1/epss",
        status=400, body="bad request",
    )
    with pytest.raises(EpssFetchError):
        FirstEPSSClient(retries=3).fetch_single("CVE-2024-0001")
    assert len(responses.calls) == 1


@responses.activate
def test_invalid_json_wrapped_as_epssfetcherror():
    responses.add(
        responses.GET, "https://api.first.org/data/v1/epss",
        body="not json", status=200, content_type="application/json",
    )
    with pytest.raises(EpssFetchError):
        FirstEPSSClient().fetch_single("CVE-2024-0001")


@responses.activate
def test_test_connection_returns_ok_on_success():
    responses.add(
        responses.GET, "https://api.first.org/data/v1/epss",
        json=_ok([{"cve": "CVE-2024-0001", "epss": "0.5",
                   "percentile": "0.5", "date": "2024-05-01"}]),
    )
    ok, msg = FirstEPSSClient().test_connection()
    assert ok and "OK" in msg


@responses.activate
def test_test_connection_returns_failure_on_5xx():
    responses.add(
        responses.GET, "https://api.first.org/data/v1/epss",
        status=503, body="boom",
    )
    ok, msg = FirstEPSSClient(retries=0).test_connection()
    assert not ok and "unreachable" in msg.lower()


def test_epss_row_drops_malformed():
    assert EpssRow.from_api({"cve": "", "epss": "1", "percentile": "1", "date": "2024-01-01"}) is None
    assert EpssRow.from_api({"cve": "CVE-1", "epss": "x", "percentile": "1", "date": "2024-01-01"}) is None
    good = EpssRow.from_api({"cve": "CVE-1", "epss": "0.1", "percentile": "0.2", "date": "2024-01-01"})
    assert good is not None and good.cve == "CVE-1"
