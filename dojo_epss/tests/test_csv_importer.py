"""Tests for the daily CSV importer."""

from __future__ import annotations

import datetime as _dt
import gzip
import io
from decimal import Decimal

import pytest
import responses

from dojo_epss.models import EPSSCVERecord, EPSSSource
from dojo_epss.services.csv_importer import download_and_parse, upsert_records
from dojo_epss.services.first_client import EpssRow


def _gz_csv(score_date, rows):
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(f"#model_version:v2024.05.01,score_date:{score_date.isoformat()}T00:00:00+0000\n".encode())
        gz.write(b"cve,epss,percentile\n")
        for cve, epss, pct in rows:
            gz.write(f"{cve},{epss},{pct}\n".encode())
    return buf.getvalue()


def _gz_csv_without_model_header(rows):
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(b"cve,epss,percentile\n")
        for cve, epss, pct in rows:
            gz.write(f"{cve},{epss},{pct}\n".encode())
    return buf.getvalue()


@responses.activate
@pytest.mark.django_db
def test_download_and_parse_happy_path(settings_row):
    settings_row.download_full_csv_enabled = True
    settings_row.save()

    target = _dt.date(2024, 5, 1)
    url = settings_row.csv_url_for(target)
    responses.add(
        responses.GET, url,
        body=_gz_csv(target, [("CVE-2024-0001", "0.5", "0.6"),
                              ("CVE-2024-0002", "0.7", "0.8")]),
        status=200, content_type="application/octet-stream",
    )

    score_date, rows, batch = download_and_parse(target, settings_row)
    assert score_date == target
    assert len(rows) == 2
    assert rows[0].cve == "CVE-2024-0001"
    assert rows[1].epss == Decimal("0.7")
    assert batch is not None
    assert batch.records_processed == 2


@responses.activate
@pytest.mark.django_db
def test_download_and_parse_uses_requested_date_when_header_missing(settings_row):
    settings_row.download_full_csv_enabled = True
    settings_row.save()

    target = _dt.date(2024, 5, 1)
    url = settings_row.csv_url_for(target)
    responses.add(
        responses.GET, url,
        body=_gz_csv_without_model_header([("CVE-2024-0001", "0.5", "0.6")]),
        status=200, content_type="application/octet-stream",
    )

    score_date, rows, _batch = download_and_parse(target, settings_row)
    assert score_date == target
    assert rows[0].score_date == target


@pytest.mark.django_db
def test_csv_skips_when_disabled(settings_row):
    settings_row.download_full_csv_enabled = False
    settings_row.save()
    score_date, rows, batch = download_and_parse(_dt.date(2024, 5, 1), settings_row)
    assert rows == []
    assert batch is None


@pytest.mark.django_db
def test_upsert_records_writes_rows():
    rows = [EpssRow("CVE-2024-0001", Decimal("0.1"), Decimal("0.2"),
                    _dt.date(2024, 5, 1), {})]
    n = upsert_records(rows, source=EPSSSource.FIRST_CSV)
    assert n == 1
    assert EPSSCVERecord.objects.count() == 1
