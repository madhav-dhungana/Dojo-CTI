"""Initial migration for dojo_epss.

Creates the first EPSS tables this app owns:
    dojo_epss_epsssettings        (singleton)
    dojo_epss_epsscverecord
    dojo_epss_findingepssupdate   (OneToOne -> dojo.Finding)
    dojo_epss_epssupdatelog
    dojo_epss_epssdownloadbatch

Dependencies:
    * settings.AUTH_USER_MODEL  (FK from EPSSSettings.updated_by /
                                 EPSSUpdateLog.requested_by)
    * dojo.__latest__           (OneToOne from FindingEPSSUpdate.finding)

The ``dojo.__latest__`` entry is the standard Django shorthand for "whatever
dojo's latest migration is at the time we run". It means the operator must
run dojo's migrations BEFORE running this one, which is the normal install
order anyway. No tables in the dojo app are touched.
"""

import django.core.validators
import django.db.models.deletion
import django.utils.timezone
from decimal import Decimal
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        # OneToOne to dojo.Finding requires dojo's table to exist.
        ("dojo", "__latest__"),
    ]

    operations = [
        # ----- 1) EPSSSettings (singleton) -------------------------------
        migrations.CreateModel(
            name="EPSSSettings",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("enabled", models.BooleanField(default=False)),
                ("fetch_recent_enabled", models.BooleanField(default=True)),
                ("download_full_csv_enabled", models.BooleanField(default=False)),
                ("compare_against_findings_enabled", models.BooleanField(default=True)),
                ("auto_update_enabled", models.BooleanField(default=False)),
                ("api_base_url", models.URLField(default="https://api.first.org/data/v1/epss")),
                ("csv_base_url", models.URLField(default="https://epss.empiricalsecurity.com")),
                ("epss_score_threshold", models.DecimalField(
                    blank=True, null=True, max_digits=8, decimal_places=6,
                    validators=[django.core.validators.MinValueValidator(Decimal("0.0")),
                                django.core.validators.MaxValueValidator(Decimal("1.0"))])),
                ("epss_percentile_threshold", models.DecimalField(
                    blank=True, null=True, max_digits=8, decimal_places=6,
                    validators=[django.core.validators.MinValueValidator(Decimal("0.0")),
                                django.core.validators.MaxValueValidator(Decimal("1.0"))])),
                ("fetch_date", models.DateField(blank=True, null=True)),
                ("result_limit", models.PositiveIntegerField(default=100)),
                ("order_by_epss_desc", models.BooleanField(default=True)),
                ("update_active_findings_only", models.BooleanField(default=True)),
                ("update_verified_findings_only", models.BooleanField(default=False)),
                ("update_severities", models.JSONField(blank=True, default=list)),
                ("update_products", models.JSONField(blank=True, default=list)),
                ("update_product_types", models.JSONField(blank=True, default=list)),
                ("update_min_epss_score", models.DecimalField(
                    default=Decimal("0.000000"), max_digits=8, decimal_places=6,
                    validators=[django.core.validators.MinValueValidator(Decimal("0.0")),
                                django.core.validators.MaxValueValidator(Decimal("1.0"))])),
                ("update_max_epss_score", models.DecimalField(
                    default=Decimal("1.000000"), max_digits=8, decimal_places=6,
                    validators=[django.core.validators.MinValueValidator(Decimal("0.0")),
                                django.core.validators.MaxValueValidator(Decimal("1.0"))])),
                ("update_min_percentile", models.DecimalField(
                    default=Decimal("0.000000"), max_digits=8, decimal_places=6,
                    validators=[django.core.validators.MinValueValidator(Decimal("0.0")),
                                django.core.validators.MaxValueValidator(Decimal("1.0"))])),
                ("update_max_percentile", models.DecimalField(
                    default=Decimal("1.000000"), max_digits=8, decimal_places=6,
                    validators=[django.core.validators.MinValueValidator(Decimal("0.0")),
                                django.core.validators.MaxValueValidator(Decimal("1.0"))])),
                ("schedule_enabled", models.BooleanField(default=False)),
                ("schedule_cron", models.CharField(default="15 2 * * *", max_length=64)),
                ("http_timeout_secs", models.PositiveIntegerField(default=30)),
                ("http_retries", models.PositiveIntegerField(default=3)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("updated_by", models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="+",
                    to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "verbose_name": "EPSS settings",
                "verbose_name_plural": "EPSS settings",
                "permissions": [
                    ("run_epss_fetch", "Can trigger an EPSS fetch / compare / update"),
                    ("view_epss_dashboard", "Can view the EPSS dashboard and logs"),
                ],
            },
        ),

        # ----- 2) EPSSCVERecord -----------------------------------------
        migrations.CreateModel(
            name="EPSSCVERecord",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("cve_id", models.CharField(db_index=True, max_length=32)),
                ("epss_score", models.DecimalField(
                    max_digits=8, decimal_places=6,
                    validators=[django.core.validators.MinValueValidator(Decimal("0.0")),
                                django.core.validators.MaxValueValidator(Decimal("1.0"))])),
                ("epss_percentile", models.DecimalField(
                    max_digits=8, decimal_places=6,
                    validators=[django.core.validators.MinValueValidator(Decimal("0.0")),
                                django.core.validators.MaxValueValidator(Decimal("1.0"))])),
                ("epss_date", models.DateField(db_index=True)),
                ("source", models.CharField(
                    choices=[("first.org", "FIRST.org REST API"),
                             ("first.org-csv", "FIRST.org daily CSV"),
                             ("manual", "Manual upload")],
                    default="first.org", max_length=32)),
                ("raw_data", models.JSONField(blank=True, default=dict)),
                ("matched_findings_count", models.PositiveIntegerField(default=0)),
                ("last_compared_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "EPSS CVE record",
                "verbose_name_plural": "EPSS CVE records",
                "ordering": ["-epss_date", "-epss_score"],
            },
        ),
        migrations.AddConstraint(
            model_name="epsscverecord",
            constraint=models.UniqueConstraint(
                fields=("cve_id", "epss_date", "source"),
                name="dojo_epss_uniq_cve_date_src"),
        ),
        migrations.AddIndex(
            model_name="epsscverecord",
            index=models.Index(fields=["-epss_date", "-epss_score"], name="epss_recent_top_idx"),
        ),
        migrations.AddIndex(
            model_name="epsscverecord",
            index=models.Index(fields=["-epss_score"], name="epss_score_desc_idx"),
        ),
        migrations.AddIndex(
            model_name="epsscverecord",
            index=models.Index(fields=["-epss_percentile"], name="epss_pctile_desc_idx"),
        ),

        # ----- 3) EPSSUpdateLog -----------------------------------------
        migrations.CreateModel(
            name="EPSSUpdateLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("action", models.CharField(
                    choices=[("fetch_recent", "Fetch recent CVEs"),
                             ("fetch_threshold", "Fetch CVEs by threshold"),
                             ("fetch_single", "Fetch single CVE"),
                             ("fetch_batch", "Fetch CVE batch"),
                             ("download_csv", "Download daily CSV"),
                             ("compare", "Compare against Findings"),
                             ("auto_update", "Auto-update Findings"),
                             ("manual_update", "Manual update")],
                    db_index=True, max_length=32)),
                ("status", models.CharField(
                    choices=[("started", "started"), ("success", "success"),
                             ("partial_success", "partial success"),
                             ("failed", "failed"), ("skipped", "skipped")],
                    db_index=True, default="started", max_length=20)),
                ("started_at", models.DateTimeField(default=django.utils.timezone.now, db_index=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("total_cves_fetched", models.PositiveIntegerField(default=0)),
                ("total_cves_saved", models.PositiveIntegerField(default=0)),
                ("total_findings_scanned", models.PositiveIntegerField(default=0)),
                ("total_matches", models.PositiveIntegerField(default=0)),
                ("total_findings_updated", models.PositiveIntegerField(default=0)),
                ("total_skipped", models.PositiveIntegerField(default=0)),
                ("total_failed", models.PositiveIntegerField(default=0)),
                ("request_params", models.JSONField(blank=True, default=dict)),
                ("error_message", models.TextField(blank=True, default="")),
                ("details", models.JSONField(blank=True, default=dict)),
                ("requested_by", models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="+",
                    to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "verbose_name": "EPSS update log",
                "verbose_name_plural": "EPSS update logs",
                "ordering": ["-started_at"],
            },
        ),

        # ----- 4) FindingEPSSUpdate (OneToOne to dojo.Finding) ----------
        migrations.CreateModel(
            name="FindingEPSSUpdate",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("cve_id", models.CharField(blank=True, db_index=True, default="", max_length=32)),
                ("epss_score", models.DecimalField(
                    blank=True, null=True, max_digits=8, decimal_places=6,
                    validators=[django.core.validators.MinValueValidator(Decimal("0.0")),
                                django.core.validators.MaxValueValidator(Decimal("1.0"))])),
                ("epss_percentile", models.DecimalField(
                    blank=True, null=True, max_digits=8, decimal_places=6,
                    validators=[django.core.validators.MinValueValidator(Decimal("0.0")),
                                django.core.validators.MaxValueValidator(Decimal("1.0"))])),
                ("epss_date", models.DateField(blank=True, null=True)),
                ("status", models.CharField(
                    choices=[("not_checked", "not checked"), ("matched", "matched"),
                             ("updated", "updated"), ("skipped", "skipped"),
                             ("failed", "failed")],
                    default="not_checked", max_length=16)),
                ("reason", models.TextField(blank=True, default="")),
                ("last_checked_at", models.DateTimeField(blank=True, null=True)),
                ("last_updated_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("finding", models.OneToOneField(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="epss_update",
                    to="dojo.finding")),
                ("source_record", models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="finding_updates",
                    to="dojo_epss.epsscverecord")),
            ],
            options={
                "verbose_name": "Finding EPSS update",
                "verbose_name_plural": "Finding EPSS updates",
            },
        ),
        migrations.AddIndex(
            model_name="findingepssupdate",
            index=models.Index(fields=["status"], name="epss_fu_status_idx"),
        ),
        migrations.AddIndex(
            model_name="findingepssupdate",
            index=models.Index(fields=["-last_updated_at"], name="epss_fu_last_upd_idx"),
        ),
        migrations.AddIndex(
            model_name="findingepssupdate",
            index=models.Index(fields=["cve_id"], name="epss_fu_cve_idx"),
        ),

        # ----- 5) EPSSDownloadBatch -------------------------------------
        migrations.CreateModel(
            name="EPSSDownloadBatch",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("epss_date", models.DateField(db_index=True)),
                ("source_url", models.URLField(max_length=512)),
                ("local_file_path", models.CharField(blank=True, default="", max_length=1024)),
                ("checksum", models.CharField(blank=True, default="", max_length=128)),
                ("status", models.CharField(
                    choices=[("started", "started"), ("success", "success"),
                             ("partial_success", "partial success"),
                             ("failed", "failed"), ("skipped", "skipped")],
                    default="started", max_length=20)),
                ("records_processed", models.PositiveIntegerField(default=0)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("processed_at", models.DateTimeField(blank=True, null=True)),
                ("log", models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="download_batches",
                    to="dojo_epss.epssupdatelog")),
            ],
            options={
                "verbose_name": "EPSS download batch",
                "verbose_name_plural": "EPSS download batches",
                "ordering": ["-created_at"],
            },
        ),
    ]
