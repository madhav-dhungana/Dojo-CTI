from django.db import models


class Product_Type(models.Model):
    name = models.CharField(max_length=255, blank=True, default="")

    class Meta:
        app_label = "dojo"


class Product(models.Model):
    name = models.CharField(max_length=255, blank=True, default="")
    prod_type = models.ForeignKey(Product_Type, null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        app_label = "dojo"


class Finding(models.Model):
    title = models.CharField(max_length=511, blank=True, default="")
    cve = models.CharField(max_length=50, blank=True, default="")
    description = models.TextField(blank=True, default="")
    references = models.TextField(blank=True, default="")
    mitigation = models.TextField(blank=True, default="")
    impact = models.TextField(blank=True, default="")
    steps_to_reproduce = models.TextField(blank=True, default="")
    component_name = models.CharField(max_length=255, blank=True, default="")
    component_version = models.CharField(max_length=255, blank=True, default="")
    severity = models.CharField(max_length=20, blank=True, default="Info")
    active = models.BooleanField(default=True)
    verified = models.BooleanField(default=False)
    epss_score = models.FloatField(null=True, blank=True, default=None)
    epss_percentile = models.FloatField(null=True, blank=True, default=None)
    known_exploited = models.BooleanField(default=False)
    ransomware_used = models.BooleanField(default=False)
    kev_date = models.DateField(null=True, blank=True)

    class Meta:
        app_label = "dojo"


class Vulnerability_Id(models.Model):
    finding = models.ForeignKey(Finding, on_delete=models.CASCADE)
    vulnerability_id = models.CharField(max_length=255, blank=True, default="")

    class Meta:
        app_label = "dojo"
