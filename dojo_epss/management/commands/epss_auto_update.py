"""manage.py epss_auto_update [--dry-run --active-only --verified-only]"""

from __future__ import annotations

from django.core.management.base import BaseCommand

from ...models import EPSSAction, EPSSLogStatus, EPSSSettings, EPSSUpdateLog
from ...services.finding_updater import auto_update


class Command(BaseCommand):
    help = (
        "Auto-update Finding.epss_score / Finding.epss_percentile for "
        "matched Findings within the configured scope."
    )

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true",
                            help="Compute decisions but write nothing.")
        parser.add_argument("--active-only", action="store_true")
        parser.add_argument("--verified-only", action="store_true")

    def handle(self, *args, **opts):
        s = EPSSSettings.load()
        if opts["active_only"]:
            s.update_active_findings_only = True
        if opts["verified_only"]:
            s.update_verified_findings_only = True

        log_row = EPSSUpdateLog.objects.create(
            action=EPSSAction.AUTO_UPDATE,
            status=EPSSLogStatus.STARTED,
            request_params=opts,
        )
        try:
            stats = auto_update(settings=s, update_log=log_row, dry_run=opts["dry_run"])
            log_row.total_findings_updated = stats["updated"]
            log_row.total_skipped = stats["skipped"]
            log_row.total_failed = stats["failed"]
            outcome = (
                EPSSLogStatus.SUCCESS if stats["failed"] == 0 else EPSSLogStatus.PARTIAL_SUCCESS
            )
            log_row.mark_finished(outcome)
            verb = "Would update" if opts["dry_run"] else "Updated"
            self.stdout.write(self.style.SUCCESS(
                f"{verb} {stats['updated']} finding(s); skipped={stats['skipped']} failed={stats['failed']}",
            ))
        except Exception as exc:  # pylint: disable=broad-except
            log_row.mark_finished(EPSSLogStatus.FAILED, error=f"{exc!s}")
            raise
