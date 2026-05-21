"""manage.py epss_fetch_recent [--limit N --epss-gt X --percentile-gt X --date YYYY-MM-DD --order]"""

from __future__ import annotations

import datetime as _dt

from django.core.management.base import BaseCommand, CommandError

from ...models import EPSSAction, EPSSLogStatus, EPSSUpdateLog
from ...services.first_client import FirstEPSSClient
from ...services.csv_importer import upsert_records
from ...services.http import EpssFetchError


class Command(BaseCommand):
    help = "Fetch recent EPSS rows from FIRST.org and upsert them locally."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=None)
        parser.add_argument("--epss-gt", type=float, default=None,
                            help="Filter to rows with EPSS score > X.")
        parser.add_argument("--percentile-gt", type=float, default=None,
                            help="Filter to rows with EPSS percentile > X.")
        parser.add_argument("--date", default=None,
                            help="Pin to a specific score date (YYYY-MM-DD).")
        parser.add_argument("--order", default=None,
                            help="Sort order, e.g. '!epss' for highest first.")

    def handle(self, *args, **opts):
        date = None
        if opts["date"]:
            try:
                date = _dt.date.fromisoformat(opts["date"])
            except ValueError as exc:
                raise CommandError(f"Invalid --date: {exc}") from exc

        log_row = EPSSUpdateLog.objects.create(
            action=EPSSAction.FETCH_RECENT,
            status=EPSSLogStatus.STARTED,
            request_params=opts,
        )
        try:
            client = FirstEPSSClient.from_settings()
            if opts["epss_gt"] is not None or opts["percentile_gt"] is not None or date or opts["order"]:
                rows = list(client.fetch_by_threshold(
                    epss_gt=opts["epss_gt"],
                    percentile_gt=opts["percentile_gt"],
                    date=date,
                    order_by_epss_desc=(opts["order"] == "!epss"),
                    limit=opts["limit"],
                ))
            else:
                rows = client.fetch_recent(limit=opts["limit"])
            written = upsert_records(rows)
            log_row.total_cves_fetched = len(rows)
            log_row.total_cves_saved = written
            log_row.mark_finished(EPSSLogStatus.SUCCESS)
            self.stdout.write(self.style.SUCCESS(
                f"EpssFetchRecent: fetched {len(rows)} rows, wrote {written}.",
            ))
        except EpssFetchError as exc:
            log_row.mark_finished(EPSSLogStatus.FAILED, error=str(exc))
            raise CommandError(str(exc)) from exc
