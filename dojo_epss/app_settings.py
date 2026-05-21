"""Constants and settings reader for dojo_epss.

Three layers of configuration, in order of precedence:

1. ``EPSSSettings`` row in the database (admin-editable from the UI).
2. ``DOJO_EPSS = {...}`` dict in DefectDojo's settings file.
3. Module-level fallbacks below (used when neither of the above exists,
   e.g. during migrations or fresh installs).
"""

from __future__ import annotations

from django.conf import settings


# ---------------------------------------------------------------------------
# URLs (configurable per spec)
# ---------------------------------------------------------------------------
DEFAULT_API_BASE_URL = "https://api.first.org/data/v1/epss"
DEFAULT_CSV_BASE_URL = "https://epss.empiricalsecurity.com"
DEFAULT_CSV_FILENAME_TEMPLATE = "epss_scores-{date}.csv.gz"
# Always-current pointer the FIRST.org mirror exposes. Use this when no
# specific date is requested — it sidesteps the "today's file isn't
# published yet" race that returns S3 403 in the early UTC hours.
DEFAULT_CSV_CURRENT_FILENAME = "epss_scores-current.csv.gz"

# ---------------------------------------------------------------------------
# CISA KEV defaults
# ---------------------------------------------------------------------------
DEFAULT_KEV_JSON_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
DEFAULT_KEV_CSV_URL = (
    "https://www.cisa.gov/sites/default/files/csv/"
    "known_exploited_vulnerabilities.csv"
)


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------
DEFAULT_HTTP_TIMEOUT_SECS = 30
DEFAULT_HTTP_RETRIES = 3
DEFAULT_HTTP_BACKOFF = 1.5
DEFAULT_USER_AGENT = "dojo_epss/0.2 (+https://github.com/madhav-dhungana/Dojo-EPSS)"

# FIRST.org documents max page size of 100 for the REST API.
API_MAX_PAGE_SIZE = 100


# ---------------------------------------------------------------------------
# Defaults that line up 1:1 with EPSSSettings model field defaults
# ---------------------------------------------------------------------------
DEFAULT_RESULT_LIMIT = 100
DEFAULT_EPSS_SCORE_THRESHOLD = None
DEFAULT_EPSS_PERCENTILE_THRESHOLD = None


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------
FULL_SYNC_LOCK_KEY = "dojo_epss:full_sync_lock"
FULL_SYNC_LOCK_TTL_SECS = 60 * 60  # one hour
KEV_SYNC_LOCK_KEY = "dojo_epss:kev_sync_lock"
KEV_SYNC_LOCK_TTL_SECS = 60 * 60  # one hour
SCHEDULE_DISPATCHER_LOCK_KEY = "dojo_epss:schedule_dispatcher_lock"
SCHEDULE_DISPATCHER_LOCK_TTL_SECS = 10 * 60


# ---------------------------------------------------------------------------
# DefectDojo integration
# ---------------------------------------------------------------------------
# App label of DefectDojo's main app — exposed in case a fork has renamed it.
DOJO_APP_LABEL = "dojo"


def _user_overrides() -> dict:
    return getattr(settings, "DOJO_EPSS", {}) or {}


def get(name: str, default):
    return _user_overrides().get(name, default)


def dojo_app_label() -> str:
    return get("DOJO_APP_LABEL", DOJO_APP_LABEL)


def base_template() -> str:
    """Template name our pages extend. Defaults to DefectDojo's 'base.html'."""
    return getattr(settings, "DOJO_EPSS_BASE_TEMPLATE", "base.html")
