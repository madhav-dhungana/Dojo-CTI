"""Daily CSV download + streaming parser.

Source URL is read from EPSSSettings.csv_base_url (configurable per spec):

    https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz

Header row format::

    #model_version:vN.NN,score_date:YYYY-MM-DDTHH:MM:SS+0000
    cve,epss,percentile

We stream-parse to avoid loading the full ~250k-row archive into memory.
"""

from __future__ import annotations

import csv
import datetime as _dt
import gzip
import io
import logging
import re
from decimal import Decimal
from typing import Iterator

from django.utils import timezone

from .. import app_settings
from ..models import (
    EPSSCVERecord,
    EPSSDownloadBatch,
    EPSSLogStatus,
    EPSSSettings,
    EPSSSource,
    EPSSUpdateLog,
)
from .first_client import EpssRow
from .http import EpssFetchError, build_session, request_with_retry

log = logging.getLogger("dojo_epss.csv_importer")

_HEADER_DATE_RE = re.compile(r"score_date:\s*(\d{4}-\d{2}-\d{2})", re.IGNORECASE)


# This function streams CSV lines. This function needs an HTTP response.
def _stream_csv_lines(resp) -> Iterator[str]:
    raw = resp.raw
    raw.decode_content = True
    fileobj = raw
    if (
        resp.headers.get("Content-Encoding", "").lower() != "gzip"
        and resp.url.endswith(".gz")
    ):
        fileobj = gzip.GzipFile(fileobj=raw)
    text = io.TextIOWrapper(fileobj, encoding="utf-8", errors="replace")
    for line in text:
        yield line.rstrip("\r\n")


# This function downloads and parses EPSS CSV. This function needs CSV settings.
def download_and_parse(
    score_date: _dt.date | None = None,
    settings: EPSSSettings | None = None,
    update_log: EPSSUpdateLog | None = None,
) -> tuple[_dt.date, list[EpssRow], EPSSDownloadBatch | None]:
    """Download the daily CSV. Returns ``(score_date, rows, batch)``.

    ``score_date=None`` (the default) fetches the always-current pointer
    'epss_scores-current.csv.gz' so we never race FIRST.org's nightly
    publish (which returns S3 403 for a date file that doesn't exist yet).
    Pass a specific date to pin to that day's snapshot.

    ``rows`` is empty (and ``batch`` is None) if CSV downloads are disabled.
    """
    s = settings or EPSSSettings.load()
    if not s.download_full_csv_enabled:
        log.info("EPSS CSV download disabled in settings; skipping.")
        return (_dt.date.today(), [], None)

    # epss_date for the batch row is the requested date if one was given,
    # otherwise "today" as a best-effort placeholder. The CSV header line
    # will tell us the real score_date once we start reading the file.
    target_date_for_record = score_date or _dt.date.today()
    url = s.csv_url_for(score_date)  # None → 'epss_scores-current.csv.gz'
    log.info("Downloading EPSS CSV from %s", url)

    batch = EPSSDownloadBatch.objects.create(
        epss_date=target_date_for_record,
        source_url=url,
        status=EPSSLogStatus.STARTED,
        log=update_log,
    )

    sess = build_session(timeout=int(s.http_timeout_secs))
    try:
        resp = request_with_retry(
            sess, "GET", url, stream=True,
            retries=int(s.http_retries),
            timeout=int(s.http_timeout_secs),
        )
    except EpssFetchError as exc:
        batch.status = EPSSLogStatus.FAILED
        batch.processed_at = timezone.now()
        batch.save(update_fields=["status", "processed_at"])
        # Improve the error message for the common case of "today's file
        # isn't published yet" so the user knows what to do.
        msg = str(exc)
        if "403" in msg or "AccessDenied" in msg:
            hint = (
                "  HINT: 403/AccessDenied from the EPSS mirror usually means "
                "the requested date's file hasn't been published yet (FIRST.org "
                "publishes around 02:00 UTC). Either retry without specifying a "
                "date — that uses the always-current pointer — or pass an earlier date."
            )
            raise EpssFetchError(f"{msg}\n{hint}") from exc
        raise

    declared_date: _dt.date | None = None
    rows: list[EpssRow] = []
    try:
        line_iter = _stream_csv_lines(resp)
        first_line = next(line_iter, "")
        if first_line.startswith("#"):
            m = _HEADER_DATE_RE.search(first_line)
            if m:
                try:
                    declared_date = _dt.date.fromisoformat(m.group(1))
                except ValueError:
                    declared_date = None
            col_header = next(line_iter, "")
        else:
            col_header = first_line

        if "cve" not in col_header.lower():
            raise EpssFetchError(f"Unexpected CSV header: {col_header!r}")

        reader = csv.DictReader(line_iter, fieldnames=["cve", "epss", "percentile"])
        for row in reader:
            cve = (row.get("cve") or "").strip().upper()
            if not cve or cve == "CVE":
                continue
            try:
                epss = Decimal(str(row["epss"]))
                pct = Decimal(str(row["percentile"]))
            except (KeyError, TypeError, ValueError):
                continue
            rows.append(EpssRow(
                cve=cve, epss=epss, percentile=pct,
                score_date=declared_date or target_date_for_record,
                raw=row,
            ))
    except Exception as exc:  # pylint: disable=broad-except
        batch.status = EPSSLogStatus.FAILED
        batch.processed_at = timezone.now()
        batch.records_processed = len(rows)
        batch.save(update_fields=["status", "processed_at", "records_processed"])
        raise EpssFetchError(f"CSV parse failed: {exc}") from exc
    finally:
        try:
            resp.close()
        except Exception:  # pragma: no cover
            pass

    final_date = declared_date or target_date_for_record
    batch.epss_date = final_date
    batch.status = EPSSLogStatus.SUCCESS
    batch.records_processed = len(rows)
    batch.processed_at = timezone.now()
    batch.save(update_fields=["epss_date", "status", "records_processed", "processed_at"])
    log.info("Parsed %d EPSS rows from CSV (score_date=%s)", len(rows), final_date)
    return final_date, rows, batch


# This function saves EPSS records. This function needs parsed EPSS rows.
def upsert_records(rows: list[EpssRow], source: str = EPSSSource.FIRST_API) -> int:
    """Bulk upsert into EPSSCVERecord (req: avoid duplicate records)."""
    if not rows:
        return 0
    try:
        from django.db import connection
        if connection.features.supports_update_conflicts:
            EPSSCVERecord.objects.bulk_create(
                [
                    EPSSCVERecord(
                        cve_id=r.cve,
                        epss_score=r.epss,
                        epss_percentile=r.percentile,
                        epss_date=r.score_date,
                        source=source,
                        raw_data=r.raw or {},
                    )
                    for r in rows
                ],
                update_conflicts=True,
                update_fields=["epss_score", "epss_percentile", "raw_data", "updated_at"],
                unique_fields=["cve_id", "epss_date", "source"],
                batch_size=2000,
            )
            return len(rows)
    except Exception as exc:  # pragma: no cover - feature-detect path
        log.warning("bulk upsert path failed (%s); falling back to per-row.", exc)

    written = 0
    for r in rows:
        EPSSCVERecord.objects.update_or_create(
            cve_id=r.cve,
            epss_date=r.score_date,
            source=source,
            defaults={
                "epss_score": r.epss,
                "epss_percentile": r.percentile,
                "raw_data": r.raw or {},
            },
        )
        written += 1
    return written
