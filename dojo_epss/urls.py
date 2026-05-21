"""URL routes for dojo_epss.

Mounted by overriding ``ROOT_URLCONF`` to ``dojo_epss._root_urls`` (which
imports DefectDojo's urlpatterns and appends ours). See _root_urls.py.

CVE-catalog URLs (cves/ and cves/<id>/) are intentionally absent — this
library is finding-driven, not catalog-driven. The EPSSCVERecord model is
still used as an internal cache but never exposed in the UI.
"""

from django.urls import path

from . import views

app_name = "dojo_epss"

urlpatterns = [
    # Read-only pages
    path("", views.dashboard, name="dashboard"),
    path("finding-matches/", views.finding_matches, name="finding_matches"),
    path("logs/", views.update_logs, name="logs"),
    path("logs/<int:pk>/", views.update_log_detail, name="log_detail"),
    path("manual/", views.manual_run, name="manual_run"),

    # Admin-only
    path("settings/", views.settings_edit, name="settings"),

    # Action endpoints (POST). Each writes an EPSSUpdateLog row.
    path("actions/firstorg-fetch/", views.action_firstorg_fetch, name="action_firstorg_fetch"),
    path("actions/download-csv/", views.action_download_csv, name="action_download_csv"),
    path("actions/compare/", views.action_compare, name="action_compare"),
    path("actions/auto-update/", views.action_auto_update, name="action_auto_update"),
    path("actions/kev-sync/", views.action_kev_sync, name="action_kev_sync"),
    path("actions/test-connection/", views.action_test_connection, name="action_test_connection"),
]
