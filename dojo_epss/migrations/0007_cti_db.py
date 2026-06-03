"""Add package-owned CTI DB catalog."""

import django.core.validators
import django.utils.timezone
from decimal import Decimal
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dojo_epss", "0006_vulncheck_poc_itw"),
    ]

    operations = [
        migrations.AddField(
            model_name="epsssettings",
            name="cti_db_enabled",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="epsssettings",
            name="cti_db_sync_epss_enabled",
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name="epsssettings",
            name="cti_db_sync_kev_enabled",
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name="epsssettings",
            name="cti_db_sync_vulncheck_enabled",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="epsssettings",
            name="cti_db_schedule_enabled",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="epsssettings",
            name="cti_db_schedule_interval_hours",
            field=models.PositiveSmallIntegerField(
                default=24,
                validators=[
                    django.core.validators.MinValueValidator(1),
                    django.core.validators.MaxValueValidator(8760),
                ],
            ),
        ),
        migrations.AddField(
            model_name="epsssettings",
            name="cti_db_last_scheduled_run_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name="epssupdatelog",
            name="action",
            field=models.CharField(
                choices=[
                    ("fetch_recent", "Fetch recent CVEs"),
                    ("fetch_threshold", "Fetch CVEs by threshold"),
                    ("fetch_single", "Fetch single CVE"),
                    ("fetch_batch", "Fetch CVE batch"),
                    ("download_csv", "Download CSV"),
                    ("compare", "Compare against Findings"),
                    ("auto_update", "Auto-update Findings"),
                    ("manual_update", "Manual update"),
                    ("kev_sync", "KEV sync"),
                    ("vulncheck_sync", "VulnCheck POC / ITW sync"),
                    ("cti_db_sync", "CTI DB sync"),
                ],
                db_index=True,
                max_length=32,
            ),
        ),
        migrations.CreateModel(
            name="CTICVERecord",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("cve_id", models.CharField(db_index=True, max_length=32, unique=True)),
                ("epss_score", models.DecimalField(
                    blank=True,
                    decimal_places=6,
                    max_digits=8,
                    null=True,
                    validators=[
                        django.core.validators.MinValueValidator(Decimal("0.0")),
                        django.core.validators.MaxValueValidator(Decimal("1.0")),
                    ],
                )),
                ("epss_percentile", models.DecimalField(
                    blank=True,
                    decimal_places=6,
                    max_digits=8,
                    null=True,
                    validators=[
                        django.core.validators.MinValueValidator(Decimal("0.0")),
                        django.core.validators.MaxValueValidator(Decimal("1.0")),
                    ],
                )),
                ("epss_date", models.DateField(blank=True, db_index=True, null=True)),
                ("epss_source", models.CharField(blank=True, default="", max_length=32)),
                ("epss_raw_data", models.JSONField(blank=True, default=dict)),
                ("known_exploited", models.BooleanField(default=False)),
                ("ransomware_used", models.BooleanField(default=False)),
                ("kev_date_added", models.DateField(blank=True, null=True)),
                ("kev_found_date", models.DateField(blank=True, null=True)),
                ("ransomware_found_date", models.DateField(blank=True, null=True)),
                ("kev_source_type", models.CharField(
                    choices=[("json", "API / JSON feed"), ("csv", "CSV feed")],
                    default="json",
                    max_length=8,
                )),
                ("kev_source_url", models.URLField(blank=True, default="", max_length=1024)),
                ("kev_raw_data", models.JSONField(blank=True, default=dict)),
                ("public_exploit_found", models.BooleanField(default=False)),
                ("exploit_in_the_wild", models.BooleanField(default=False)),
                ("commercial_exploit_found", models.BooleanField(default=False)),
                ("weaponized_exploit_found", models.BooleanField(default=False)),
                ("reported_exploited_by_threat_actors", models.BooleanField(default=False)),
                ("reported_exploited_by_ransomware", models.BooleanField(default=False)),
                ("reported_exploited_by_botnets", models.BooleanField(default=False)),
                ("reported_exploited_by_honeypot_service", models.BooleanField(default=False)),
                ("reported_exploited_by_vulncheck_canaries", models.BooleanField(default=False)),
                ("in_cisa_kev", models.BooleanField(default=False)),
                ("in_vulncheck_kev", models.BooleanField(default=False)),
                ("max_exploit_maturity", models.CharField(blank=True, default="", max_length=64)),
                ("poc_found_date", models.DateField(blank=True, null=True)),
                ("itw_found_date", models.DateField(blank=True, null=True)),
                ("exploit_count", models.PositiveIntegerField(default=0)),
                ("vulncheck_source_index", models.CharField(blank=True, default="", max_length=128)),
                ("vulncheck_source_links", models.JSONField(blank=True, default=list)),
                ("vulncheck_raw_data", models.JSONField(blank=True, default=dict)),
                ("first_seen_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("last_seen_at", models.DateTimeField(blank=True, null=True)),
                ("last_changed_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "CTI CVE record",
                "verbose_name_plural": "CTI CVE records",
                "ordering": ["-epss_score", "cve_id"],
            },
        ),
        migrations.AddIndex(
            model_name="cticverecord",
            index=models.Index(fields=["-epss_score"], name="cti_epss_score_idx"),
        ),
        migrations.AddIndex(
            model_name="cticverecord",
            index=models.Index(fields=["known_exploited"], name="cti_kev_idx"),
        ),
        migrations.AddIndex(
            model_name="cticverecord",
            index=models.Index(fields=["ransomware_used"], name="cti_rw_idx"),
        ),
        migrations.AddIndex(
            model_name="cticverecord",
            index=models.Index(fields=["public_exploit_found"], name="cti_poc_idx"),
        ),
        migrations.AddIndex(
            model_name="cticverecord",
            index=models.Index(fields=["exploit_in_the_wild"], name="cti_itw_idx"),
        ),
        migrations.AddIndex(
            model_name="cticverecord",
            index=models.Index(fields=["-updated_at"], name="cti_updated_idx"),
        ),
    ]
