"""Root URLconf wrapper used when ROOT_URLCONF=dojo_epss._root_urls.

We can't safely call ``include("dojo_epss.urls", ...)`` from
``local_settings.py``: that runs at settings-load time, before Django's app
registry is ready. Defining Django models requires the app registry to be
ready, so the import chain `urls → views → forms → models` raises
``AppRegistryNotReady``.

Instead we point ``ROOT_URLCONF`` at THIS module (which is just a string at
settings load — no imports yet). Django imports the URLconf much later,
during request setup / runserver bootstrap, by which time the app registry
is fully populated and our models can import cleanly.

This wrapper preserves DefectDojo's full URL surface (including
``EXTRA_URL_PATTERNS``, which ``dojo.urls`` already appends at its module
bottom) and adds our ``/epss/`` namespace on top.
"""

from __future__ import annotations

from django.urls import include, path, re_path

from dojo_epss.api import FindingEPSSMatchListAPIView

# Import dojo's URLconf — by the time Django evaluates this module the
# app registry is ready, so this is safe.
from dojo.urls import urlpatterns as _dojo_urlpatterns

# This route is package-owned, so it appears in Swagger without editing Dojo core.
urlpatterns = [
    re_path(
        r"^api/v2/dojo_epss/finding-matches/$",
        FindingEPSSMatchListAPIView.as_view(),
        name="dojo_epss_api_finding_matches",
    ),
] + list(_dojo_urlpatterns) + [
    path("epss/", include("dojo_epss.urls", namespace="dojo_epss")),
]
