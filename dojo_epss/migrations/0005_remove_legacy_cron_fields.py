"""Remove legacy documentation-only cron fields.

Runtime scheduling is now controlled entirely by the interval fields added in
0004 and the static Celery beat dispatcher installed by the overlay.
"""

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("dojo_epss", "0004_interval_scheduler"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="epsssettings",
            name="schedule_cron",
        ),
        migrations.RemoveField(
            model_name="epsssettings",
            name="kev_schedule_cron",
        ),
    ]
