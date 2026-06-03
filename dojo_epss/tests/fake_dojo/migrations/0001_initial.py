from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Product_Type",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("name", models.CharField(blank=True, default="", max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name="Product",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("name", models.CharField(blank=True, default="", max_length=255)),
                ("prod_type", models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    to="dojo.product_type",
                )),
            ],
        ),
        migrations.CreateModel(
            name="Finding",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("title", models.CharField(blank=True, default="", max_length=511)),
                ("cve", models.CharField(blank=True, default="", max_length=50)),
                ("description", models.TextField(blank=True, default="")),
                ("references", models.TextField(blank=True, default="")),
                ("mitigation", models.TextField(blank=True, default="")),
                ("impact", models.TextField(blank=True, default="")),
                ("steps_to_reproduce", models.TextField(blank=True, default="")),
                ("component_name", models.CharField(blank=True, default="", max_length=255)),
                ("component_version", models.CharField(blank=True, default="", max_length=255)),
                ("severity", models.CharField(blank=True, default="Info", max_length=20)),
                ("active", models.BooleanField(default=True)),
                ("verified", models.BooleanField(default=False)),
                ("epss_score", models.FloatField(blank=True, default=None, null=True)),
                ("epss_percentile", models.FloatField(blank=True, default=None, null=True)),
                ("known_exploited", models.BooleanField(default=False)),
                ("ransomware_used", models.BooleanField(default=False)),
                ("kev_date", models.DateField(blank=True, null=True)),
            ],
        ),
        migrations.CreateModel(
            name="Vulnerability_Id",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("vulnerability_id", models.CharField(blank=True, default="", max_length=255)),
                ("finding", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    to="dojo.finding",
                )),
            ],
        ),
    ]
