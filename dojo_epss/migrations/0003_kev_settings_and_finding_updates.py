"""Add KEV settings and per-Finding KEV update state.

This migration is additive and only creates/extends dojo_epss-owned tables.
It does not alter any DefectDojo core table. Runtime KEV sync writes to
existing dojo.Finding fields only when a matching CVE is found.
"""

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dojo_epss", "0002_epsssettings_auto_chain_after_fetch"),
        ("dojo", "__latest__"),
    ]

    operations = [
        migrations.AddField(
            model_name="epsssettings",
            name="kev_enabled",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="epsssettings",
            name="kev_source_type",
            field=models.CharField(
                choices=[("json", "API / JSON feed"), ("csv", "CSV feed")],
                default="json",
                max_length=8,
            ),
        ),
        migrations.AddField(
            model_name="epsssettings",
            name="kev_source_url",
            field=models.URLField(
                default=(
                    "https://www.cisa.gov/sites/default/files/feeds/"
                    "known_exploited_vulnerabilities.json"
                ),
                max_length=1024,
            ),
        ),
        migrations.AddField(
            model_name="epsssettings",
            name="kev_update_findings_enabled",
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name="epsssettings",
            name="kev_schedule_enabled",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="epsssettings",
            name="kev_schedule_cron",
            field=models.CharField(default="45 2 * * *", max_length=64),
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
                ],
                db_index=True,
                max_length=32,
            ),
        ),
        migrations.CreateModel(
            name="FindingKEVUpdate",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("cve_id", models.CharField(blank=True, db_index=True, default="", max_length=32)),
                ("known_exploited", models.BooleanField(default=False)),
                ("ransomware_used", models.BooleanField(default=False)),
                ("kev_found_date", models.DateField(blank=True, null=True)),
                ("ransomware_found_date", models.DateField(blank=True, null=True)),
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
                ("source_type", models.CharField(
                    choices=[("json", "API / JSON feed"), ("csv", "CSV feed")],
                    default="json",
                    max_length=8,
                )),
                ("source_url", models.URLField(blank=True, default="", max_length=1024)),
                ("raw_data", models.JSONField(blank=True, default=dict)),
                ("last_checked_at", models.DateTimeField(blank=True, null=True)),
                ("last_updated_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("finding", models.OneToOneField(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="kev_update",
                    to="dojo.finding",
                )),
            ],
            options={
                "verbose_name": "Finding KEV update",
                "verbose_name_plural": "Finding KEV updates",
            },
        ),
        migrations.AddIndex(
            model_name="findingkevupdate",
            index=models.Index(fields=["status"], name="kev_fu_status_idx"),
        ),
        migrations.AddIndex(
            model_name="findingkevupdate",
            index=models.Index(fields=["cve_id"], name="kev_fu_cve_idx"),
        ),
        migrations.AddIndex(
            model_name="findingkevupdate",
            index=models.Index(fields=["kev_found_date"], name="kev_fu_found_idx"),
        ),
        migrations.AddIndex(
            model_name="findingkevupdate",
            index=models.Index(fields=["-last_updated_at"], name="kev_fu_last_upd_idx"),
        ),
    ]
