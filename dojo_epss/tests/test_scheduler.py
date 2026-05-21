"""Tests for the scheduler / full-sync orchestrator."""

from __future__ import annotations

import datetime as _dt

import pytest
from django.utils import timezone

from dojo_epss.models import EPSSLogStatus, EPSSSettings, EPSSUpdateLog
from dojo_epss.services.scheduler import full_sync_lock, run_full_sync
from dojo_epss.tasks import _interval_due


@pytest.mark.django_db
def test_full_sync_skips_when_module_disabled(settings_row):
    settings_row.enabled = False
    settings_row.save()
    log_id = run_full_sync()
    log = EPSSUpdateLog.objects.get(pk=log_id)
    assert log.status == EPSSLogStatus.SKIPPED
    assert "disabled" in log.error_message


@pytest.mark.django_db
def test_full_sync_lock_prevents_overlap():
    with full_sync_lock() as got_outer:
        assert got_outer is True
        with full_sync_lock() as got_inner:
            assert got_inner is False
    # After exit the lock is released.
    with full_sync_lock() as got_after:
        assert got_after is True


def test_interval_due_supports_12_and_24_hours():
    now = timezone.now()
    assert _interval_due(None, 12, now) is True
    assert _interval_due(now - _dt.timedelta(hours=11, minutes=59), 12, now) is False
    assert _interval_due(now - _dt.timedelta(hours=12), 12, now) is True
    assert _interval_due(now - _dt.timedelta(hours=23, minutes=59), 24, now) is False
    assert _interval_due(now - _dt.timedelta(hours=24), 24, now) is True
