"""Add UI-controlled interval scheduler fields.

The old cron text fields remain for backwards compatibility. Runtime
scheduling is controlled by a static Celery beat dispatcher plus these
interval/last-run fields.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dojo_epss", "0003_kev_settings_and_finding_updates"),
    ]

    operations = [
        migrations.AddField(
            model_name="epsssettings",
            name="schedule_interval_hours",
            field=models.PositiveSmallIntegerField(
                choices=[(12, "Every 12 hours"), (24, "Every 24 hours")],
                default=24,
            ),
        ),
        migrations.AddField(
            model_name="epsssettings",
            name="epss_last_scheduled_run_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="epsssettings",
            name="kev_schedule_interval_hours",
            field=models.PositiveSmallIntegerField(
                choices=[(12, "Every 12 hours"), (24, "Every 24 hours")],
                default=24,
            ),
        ),
        migrations.AddField(
            model_name="epsssettings",
            name="kev_last_scheduled_run_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
