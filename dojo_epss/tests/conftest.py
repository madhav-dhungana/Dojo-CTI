"""Pytest fixtures for dojo_epss tests.

Standalone Django configuration — does NOT require a real DefectDojo install.
Tests that exercise the OneToOne relationship to dojo.Finding use a small
"fake_dojo" app declared inside this conftest that provides a stand-in
``Finding`` model with the relevant fields (cve, epss_score, epss_percentile,
severity, active, verified). The OneToOne in dojo_epss resolves to this
stand-in when running ``pytest`` outside of DefectDojo.
"""

from __future__ import annotations

import django
import pytest
from django.conf import settings


def pytest_configure():
    if settings.configured:
        return
    settings.configure(
        DEBUG=False,
        DATABASES={
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": ":memory:",
            },
        },
        INSTALLED_APPS=[
            "django.contrib.auth",
            "django.contrib.contenttypes",
            "dojo_epss.tests.fake_dojo",   # provides a fake `dojo` app label
            "dojo_epss",
        ],
        DEFAULT_AUTO_FIELD="django.db.models.BigAutoField",
        ROOT_URLCONF="dojo_epss.urls",
        CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
        USE_TZ=True,
        TIME_ZONE="UTC",
        TEMPLATES=[{
            "BACKEND": "django.template.backends.django.DjangoTemplates",
            "APP_DIRS": True,
            "OPTIONS": {"context_processors": []},
        }],
    )
    django.setup()


@pytest.fixture
def settings_row(db):
    from dojo_epss.models import EPSSSettings
    return EPSSSettings.load()


@pytest.fixture
def fake_finding(db):
    """Create a fake-dojo Finding row for matcher / updater tests."""
    from dojo_epss.tests.fake_dojo.models import Finding, Vulnerability_Id
    f = Finding.objects.create(
        title="Test", cve="CVE-2024-0001",
        severity="High", active=True, verified=True,
    )
    Vulnerability_Id.objects.create(finding=f, vulnerability_id="CVE-2024-0002")
    return f
