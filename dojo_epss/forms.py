"""Admin forms for the /epss/settings/ page."""

from __future__ import annotations

import logging
from decimal import Decimal

from django import forms
from django.apps import apps

from . import app_settings
from .models import EPSSSettings, EPSSSeverity, KEVSourceType

log = logging.getLogger("dojo_epss.forms")


# This function loads a DefectDojo model. This function needs a model name.
def _get_dojo_model(name: str):
    """Return dojo.<name> if importable, else None."""
    try:
        return apps.get_model(app_settings.dojo_app_label(), name)
    except Exception:
        return None


class EPSSSettingsForm(forms.ModelForm):
    """One form covering every admin-editable knob (req #2, #5–#10).

    Product and Product_Type are presented as multi-select dropdowns showing
    actual names. They're stored back into the model's JSONField as a plain
    list of int IDs so the matcher can read them at runtime without an extra
    join.
    """

    FETCH_SOURCE_FIRSTORG = "firstorg"
    FETCH_SOURCE_CSV = "csv"
    FETCH_SOURCE_CHOICES = (
        (FETCH_SOURCE_FIRSTORG, "Fetch and compare from FIRST.org"),
        (FETCH_SOURCE_CSV, "Download CSV and compare"),
    )
    SCHEDULE_INTERVAL_CHOICES = (
        ("0", "Disabled"),
        ("12", "Every 12 hours"),
        ("24", "Every 24 hours"),
    )

    fetch_source = forms.ChoiceField(
        choices=FETCH_SOURCE_CHOICES,
        widget=forms.RadioSelect,
        help_text=(
            "Choose exactly one EPSS source. The Manual Run page shows the "
            "matching action button."
        ),
    )

    kev_source_type = forms.ChoiceField(
        label="KEV source type",
        choices=KEVSourceType.choices,
        widget=forms.RadioSelect,
        help_text="Choose the Source Format Type",
    )

    epss_schedule_interval = forms.ChoiceField(
        label="EPSS scheduled sync",
        choices=SCHEDULE_INTERVAL_CHOICES,
        help_text="Schedule the Celery Job run for the EPSS scan",
    )

    kev_schedule_interval = forms.ChoiceField(
        label="KEV scheduled sync",
        choices=SCHEDULE_INTERVAL_CHOICES,
        help_text="Schedule the Celery Job run for the KEV scan",
    )

    update_severities = forms.MultipleChoiceField(
        choices=EPSSSeverity.choices,
        required=False,
        widget=forms.CheckboxSelectMultiple,
        help_text="Severities eligible for auto-update. Leave all unchecked = all severities.",
    )

    update_products = forms.ModelMultipleChoiceField(
        queryset=None,  # populated in __init__
        required=False,
        widget=forms.SelectMultiple(attrs={
            "class": "form-control",
            "size": "8",
            "style": "min-height: 9em;",
        }),
        help_text=(
            "Hold Ctrl/Cmd to select multiple. Leave empty = all products. "
            "Only matched findings whose product is in this list will be auto-updated."
        ),
    )

    update_product_types = forms.ModelMultipleChoiceField(
        queryset=None,
        required=False,
        widget=forms.SelectMultiple(attrs={
            "class": "form-control",
            "size": "6",
            "style": "min-height: 7em;",
        }),
        help_text=(
            "Hold Ctrl/Cmd to select multiple. Leave empty = all product types."
        ),
    )

    class Meta:
        model = EPSSSettings
        fields = [
            # Master switches
            "enabled",
            "fetch_source",
            "compare_against_findings_enabled",
            "auto_update_enabled",
            # KEV
            "kev_enabled",
            "kev_source_type",
            "kev_source_url",
            "kev_update_findings_enabled",
            # URLs
            "api_base_url",
            "csv_base_url",
            # Thresholds
            "epss_score_threshold",
            "epss_percentile_threshold",
            "fetch_date",
            "result_limit",
            "order_by_epss_desc",
            # Auto-update scope
            "update_active_findings_only",
            "update_verified_findings_only",
            "update_severities",
            "update_products",
            "update_product_types",
            "update_min_epss_score",
            "update_max_epss_score",
            "update_min_percentile",
            "update_max_percentile",
            # Schedule
            "epss_schedule_interval",
            "kev_schedule_interval",
            # HTTP
            "http_timeout_secs",
            "http_retries",
        ]
        widgets = {
            "fetch_date": forms.DateInput(attrs={"type": "date"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Wire the Product / Product_Type querysets. If dojo isn't importable
        # (test env), present an empty queryset and a help message — the form
        # still works for everything else.
        Product = _get_dojo_model("Product")
        Product_Type = _get_dojo_model("Product_Type")
        if Product is not None:
            self.fields["update_products"].queryset = Product.objects.all().order_by("name")
        else:
            self.fields["update_products"].queryset = []
            self.fields["update_products"].help_text = (
                "Product model not available — dojo not installed in this Python env."
            )
        if Product_Type is not None:
            self.fields["update_product_types"].queryset = Product_Type.objects.all().order_by("name")
        else:
            self.fields["update_product_types"].queryset = []
            self.fields["update_product_types"].help_text = (
                "Product_Type model not available — dojo not installed in this Python env."
            )

        self.fields["kev_enabled"].label = "KEV enabled"
        self.fields["kev_enabled"].help_text = "Enable KEV Checks"
        self.fields["kev_source_url"].label = "KEV source URL"
        self.fields["kev_update_findings_enabled"].label = "KEV update findings enabled"

        # Populate initial selections from the JSONField on the instance.
        instance = kwargs.get("instance")
        if instance:
            self.initial.setdefault(
                "fetch_source",
                self.FETCH_SOURCE_CSV
                if instance.download_full_csv_enabled and not instance.fetch_recent_enabled
                else self.FETCH_SOURCE_FIRSTORG,
            )
            self.initial.setdefault("update_severities", instance.severities_list())
            if instance.update_products:
                self.initial["update_products"] = instance.product_id_list()
            if instance.update_product_types:
                self.initial["update_product_types"] = instance.product_type_id_list()
            self.initial.setdefault("kev_source_type", instance.kev_source_type or KEVSourceType.JSON)
            self.initial.setdefault(
                "epss_schedule_interval",
                str(instance.schedule_interval_hours if instance.schedule_enabled else 0),
            )
            self.initial.setdefault(
                "kev_schedule_interval",
                str(instance.kev_schedule_interval_hours if instance.kev_schedule_enabled else 0),
            )

    # ----- value coercion: ModelMultipleChoiceField yields a QuerySet; the
    # underlying JSONField wants a plain list of int PKs.
    # This function cleans severity choices. This function needs form data.
    def clean_update_severities(self):
        return [s for s in self.cleaned_data.get("update_severities") or [] if s]

    # This function cleans product choices. This function needs selected products.
    def clean_update_products(self):
        qs = self.cleaned_data.get("update_products") or []
        return [int(obj.pk) for obj in qs]

    # This function cleans product type choices. This function needs selected product types.
    def clean_update_product_types(self):
        qs = self.cleaned_data.get("update_product_types") or []
        return [int(obj.pk) for obj in qs]

    # This function validates settings. This function needs submitted settings data.
    def clean(self):
        cleaned = super().clean()

        if cleaned.get("fetch_source") not in {
            self.FETCH_SOURCE_FIRSTORG,
            self.FETCH_SOURCE_CSV,
        }:
            self.add_error("fetch_source", "Choose one EPSS source.")
        else:
            self.instance.fetch_recent_enabled = cleaned["fetch_source"] == self.FETCH_SOURCE_FIRSTORG
            self.instance.download_full_csv_enabled = cleaned["fetch_source"] == self.FETCH_SOURCE_CSV

        for f in (
            "epss_score_threshold", "epss_percentile_threshold",
            "update_min_epss_score", "update_max_epss_score",
            "update_min_percentile", "update_max_percentile",
        ):
            v = cleaned.get(f)
            if v is None:
                continue
            if v < Decimal("0") or v > Decimal("1"):
                self.add_error(f, "Must be between 0.0 and 1.0.")
        if cleaned.get("update_min_epss_score", Decimal("0")) > cleaned.get("update_max_epss_score", Decimal("1")):
            self.add_error("update_max_epss_score", "Max must be ≥ min.")
        if cleaned.get("update_min_percentile", Decimal("0")) > cleaned.get("update_max_percentile", Decimal("1")):
            self.add_error("update_max_percentile", "Max must be ≥ min.")

        if cleaned.get("kev_source_type") not in {KEVSourceType.JSON, KEVSourceType.CSV}:
            self.add_error("kev_source_type", "Choose one KEV source format.")
        else:
            # If the operator changes only the CISA source format radio, keep
            # the URL in sync with the matching CISA default. Custom URLs are
            # left untouched.
            url = cleaned.get("kev_source_url")
            cisa_defaults = {
                KEVSourceType.JSON.value: app_settings.DEFAULT_KEV_JSON_URL,
                KEVSourceType.CSV.value: app_settings.DEFAULT_KEV_CSV_URL,
            }
            if url in set(cisa_defaults.values()):
                cleaned["kev_source_url"] = cisa_defaults[cleaned["kev_source_type"]]
        if cleaned.get("kev_enabled") and not cleaned.get("kev_source_url"):
            self.add_error("kev_source_url", "Enter a KEV source URL.")

        for field in ("epss_schedule_interval", "kev_schedule_interval"):
            if cleaned.get(field) not in {"0", "12", "24"}:
                self.add_error(field, "Choose Disabled, Every 12 hours, or Every 24 hours.")
        return cleaned

    # This function saves settings choices. This function needs valid cleaned data.
    def save(self, commit=True):
        obj = super().save(commit=False)
        source = self.cleaned_data.get("fetch_source") or self.FETCH_SOURCE_FIRSTORG
        obj.fetch_recent_enabled = source == self.FETCH_SOURCE_FIRSTORG
        obj.download_full_csv_enabled = source == self.FETCH_SOURCE_CSV

        epss_interval = self.cleaned_data.get("epss_schedule_interval") or "0"
        obj.schedule_enabled = epss_interval != "0"
        if epss_interval != "0":
            obj.schedule_interval_hours = int(epss_interval)

        kev_interval = self.cleaned_data.get("kev_schedule_interval") or "0"
        obj.kev_schedule_enabled = kev_interval != "0"
        if kev_interval != "0":
            obj.kev_schedule_interval_hours = int(kev_interval)

        if commit:
            obj.save()
            self.save_m2m()
        return obj
