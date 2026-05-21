"""Add EPSSSettings.auto_chain_after_fetch boolean.

When False (default), the 'Manual Fetch from FIRST.org' and 'Manual
download CSV' buttons only fetch — compare and auto-update are separate
operator clicks. When True, fetch buttons run the full pipeline.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dojo_epss", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="epsssettings",
            name="auto_chain_after_fetch",
            field=models.BooleanField(default=False),
        ),
    ]
