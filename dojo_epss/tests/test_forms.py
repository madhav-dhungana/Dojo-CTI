"""Tests for EPSS settings form behavior."""

from __future__ import annotations

import pytest

from dojo_epss import app_settings
from dojo_epss.forms import EPSSSettingsForm


def _settings_form_data(source: str) -> dict:
    return {
        "enabled": "on",
        "fetch_source": source,
        "compare_against_findings_enabled": "on",
        "kev_source_type": "json",
        "kev_source_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "kev_update_findings_enabled": "on",
        "api_base_url": "https://api.first.org/data/v1/epss",
        "csv_base_url": "https://epss.empiricalsecurity.com",
        "result_limit": "100",
        "order_by_epss_desc": "on",
        "update_active_findings_only": "on",
        "update_min_epss_score": "0.000000",
        "update_max_epss_score": "1.000000",
        "update_min_percentile": "0.000000",
        "update_max_percentile": "1.000000",
        "epss_schedule_interval": "0",
        "kev_schedule_interval": "0",
        "http_timeout_secs": "30",
        "http_retries": "3",
    }


@pytest.mark.django_db
def test_settings_form_saves_firstorg_as_only_fetch_source(settings_row):
    form = EPSSSettingsForm(_settings_form_data("firstorg"), instance=settings_row)
    assert form.is_valid(), form.errors
    obj = form.save()
    assert obj.fetch_recent_enabled is True
    assert obj.download_full_csv_enabled is False


@pytest.mark.django_db
def test_settings_form_saves_csv_as_only_fetch_source(settings_row):
    form = EPSSSettingsForm(_settings_form_data("csv"), instance=settings_row)
    assert form.is_valid(), form.errors
    obj = form.save()
    assert obj.fetch_recent_enabled is False
    assert obj.download_full_csv_enabled is True


@pytest.mark.django_db
def test_settings_form_switches_cisa_kev_default_url_for_csv(settings_row):
    data = _settings_form_data("firstorg")
    data["kev_source_type"] = "csv"
    data["kev_source_url"] = app_settings.DEFAULT_KEV_JSON_URL
    form = EPSSSettingsForm(data, instance=settings_row)
    assert form.is_valid(), form.errors
    obj = form.save()
    assert obj.kev_source_url == app_settings.DEFAULT_KEV_CSV_URL


@pytest.mark.django_db
def test_settings_form_saves_ui_schedule_intervals(settings_row):
    data = _settings_form_data("firstorg")
    data["epss_schedule_interval"] = "12"
    data["kev_schedule_interval"] = "24"
    form = EPSSSettingsForm(data, instance=settings_row)
    assert form.is_valid(), form.errors
    obj = form.save()
    assert obj.schedule_enabled is True
    assert obj.schedule_interval_hours == 12
    assert obj.kev_schedule_enabled is True
    assert obj.kev_schedule_interval_hours == 24
