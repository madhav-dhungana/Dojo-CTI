"""manage.py epss_download_csv [--date YYYY-MM-DD]"""

from __future__ import annotations

import datetime as _dt

from django.core.management.base import BaseCommand, CommandError

from ...models import EPSSAction, EPSSLogStatus, EPSSUpdateLog
from ...services.epss_importer import import_csv
from ...services.http import EpssFetchError


class Command(BaseCommand):
    help = "Download the daily EPSS CSV from FIRST.org and upsert rows."

    def add_arguments(self, parser):
        parser.add_argument("--date", default=None,
                            help="Optional score_date (YYYY-MM-DD).")

    def handle(self, *args, **opts):
        date = None
        if opts["date"]:
            try:
                date = _dt.date.fromisoformat(opts["date"])
            except ValueError as exc:
                raise CommandError(f"Invalid --date: {exc}") from exc

        log_row = EPSSUpdateLog.objects.create(
            action=EPSSAction.DOWNLOAD_CSV,
            status=EPSSLogStatus.STARTED,
            request_params=opts,
        )
        try:
            final_date, rows, written = import_csv(date, update_log=log_row)
            log_row.total_cves_fetched = len(rows)
            log_row.total_cves_saved = written
            log_row.mark_finished(EPSSLogStatus.SUCCESS)
            self.stdout.write(self.style.SUCCESS(
                f"CSV import: date={final_date} rows={len(rows)} written={written}.",
            ))
        except EpssFetchError as exc:
            log_row.mark_finished(EPSSLogStatus.FAILED, error=str(exc))
            raise CommandError(str(exc)) from exc
