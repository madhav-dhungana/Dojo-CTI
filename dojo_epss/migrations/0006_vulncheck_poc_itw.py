"""Add VulnCheck POC / ITW settings and per-Finding update state."""

import django.core.validators
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dojo_epss", "0005_remove_legacy_cron_fields"),
        ("dojo", "__latest__"),
    ]

    operations = [
        migrations.AlterField(
            model_name="epsssettings",
            name="schedule_interval_hours",
            field=models.PositiveSmallIntegerField(
                default=24,
                validators=[
                    django.core.validators.MinValueValidator(1),
                    django.core.validators.MaxValueValidator(8760),
                ],
            ),
        ),
        migrations.AlterField(
            model_name="epsssettings",
            name="kev_schedule_interval_hours",
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
            name="vulncheck_enabled",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="epsssettings",
            name="vulncheck_api_base_url",
            field=models.URLField(default="https://api.vulncheck.com/v3", max_length=512),
        ),
        migrations.AddField(
            model_name="epsssettings",
            name="vulncheck_index",
            field=models.CharField(default="exploits", max_length=128),
        ),
        migrations.AddField(
            model_name="epsssettings",
            name="vulncheck_api_token_encrypted",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="epsssettings",
            name="vulncheck_schedule_enabled",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="epsssettings",
            name="vulncheck_schedule_interval_hours",
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
            name="vulncheck_last_scheduled_run_at",
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
                ],
                db_index=True,
                max_length=32,
            ),
        ),
        migrations.CreateModel(
            name="FindingVulnCheckUpdate",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("cve_id", models.CharField(blank=True, db_index=True, default="", max_length=32)),
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
                ("source_index", models.CharField(blank=True, default="", max_length=128)),
                ("source_links", models.JSONField(blank=True, default=list)),
                ("raw_data", models.JSONField(blank=True, default=dict)),
                ("status", models.CharField(
                    choices=[
                        ("not_checked", "not checked"),
                        ("matched", "matched"),
                        ("updated", "updated"),
                        ("skipped", "skipped"),
                        ("failed", "failed"),
                    ],
                    default="not_checked",
                    max_length=16,
                )),
                ("reason", models.TextField(blank=True, default="")),
                ("last_checked_at", models.DateTimeField(blank=True, null=True)),
                ("last_updated_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("finding", models.OneToOneField(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="vulncheck_update",
                    to="dojo.finding",
                )),
            ],
            options={
                "verbose_name": "Finding VulnCheck update",
                "verbose_name_plural": "Finding VulnCheck updates",
            },
        ),
        migrations.AddIndex(
            model_name="findingvulncheckupdate",
            index=models.Index(fields=["status"], name="vc_fu_status_idx"),
        ),
        migrations.AddIndex(
            model_name="findingvulncheckupdate",
            index=models.Index(fields=["cve_id"], name="vc_fu_cve_idx"),
        ),
        migrations.AddIndex(
            model_name="findingvulncheckupdate",
            index=models.Index(fields=["public_exploit_found"], name="vc_fu_poc_idx"),
        ),
        migrations.AddIndex(
            model_name="findingvulncheckupdate",
            index=models.Index(fields=["exploit_in_the_wild"], name="vc_fu_itw_idx"),
        ),
        migrations.AddIndex(
            model_name="findingvulncheckupdate",
            index=models.Index(fields=["-last_updated_at"], name="vc_fu_last_upd_idx"),
        ),
    ]
