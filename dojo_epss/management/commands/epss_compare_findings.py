"""manage.py epss_compare_findings [--active-only --verified-only --product N --product-type N --severity Critical]"""

from __future__ import annotations

from django.core.management.base import BaseCommand

from ...models import EPSSAction, EPSSLogStatus, EPSSSettings, EPSSUpdateLog
from ...services.finding_matcher import compare


class Command(BaseCommand):
    help = "Compare stored EPSS CVE records against existing DefectDojo Findings."

    def add_arguments(self, parser):
        parser.add_argument("--active-only", action="store_true",
                            help="Apply EPSSSettings.update_active_findings_only=True for this run.")
        parser.add_argument("--verified-only", action="store_true",
                            help="Apply EPSSSettings.update_verified_findings_only=True for this run.")
        parser.add_argument("--product", action="append", type=int, default=[],
                            help="Limit to a specific dojo Product id (repeatable).")
        parser.add_argument("--product-type", action="append", type=int, default=[],
                            help="Limit to a specific dojo Product_Type id (repeatable).")
        parser.add_argument("--severity", action="append", default=[],
                            help="Limit to a specific severity (repeatable).")

    def handle(self, *args, **opts):
        s = EPSSSettings.load()
        # Apply flag-based overrides as a *temporary* in-memory mutation; we
        # don't .save() so the persisted singleton is untouched.
        if opts["active_only"]:
            s.update_active_findings_only = True
        if opts["verified_only"]:
            s.update_verified_findings_only = True
        if opts["product"]:
            s.update_products = opts["product"]
        if opts["product_type"]:
            s.update_product_types = opts["product_type"]
        if opts["severity"]:
            s.update_severities = opts["severity"]

        log_row = EPSSUpdateLog.objects.create(
            action=EPSSAction.COMPARE,
            status=EPSSLogStatus.STARTED,
            request_params=opts,
        )
        try:
            stats = compare(settings=s, update_log=log_row)
            log_row.total_findings_scanned = stats["scanned"]
            log_row.total_matches = stats["matched"]
            log_row.mark_finished(EPSSLogStatus.SUCCESS)
            self.stdout.write(self.style.SUCCESS(
                f"Compared: scanned={stats['scanned']} matched={stats['matched']}",
            ))
        except Exception as exc:  # pylint: disable=broad-except
            log_row.mark_finished(EPSSLogStatus.FAILED, error=f"{exc!s}")
            raise
