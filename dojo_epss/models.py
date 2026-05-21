"""Models for dojo_epss.

Six tables, all owned by this app's app_label:

* ``EPSSSettings``       — singleton, admin-editable runtime config.
* ``EPSSCVERecord``      — fetched EPSS rows; UNIQUE(cve_id, epss_date, source).
* ``FindingEPSSUpdate``  — OneToOne back to ``dojo.Finding``; tracks per-Finding
                            enrichment state without duplicating Finding's
                            existing ``epss_score`` / ``epss_percentile`` fields.
* ``FindingKEVUpdate``   — OneToOne back to ``dojo.Finding``; tracks per-Finding
                            KEV/ransomware state discovered by this library.
* ``EPSSUpdateLog``      — one row per fetch / compare / download / update action.
* ``EPSSDownloadBatch``  — one row per full-CSV download attempt; links to a log.

Design rules confirmed by inspecting DefectDojo 2.58.2:

  * Finding already has ``epss_score`` (FloatField 0.0-1.0), ``epss_percentile``,
    ``known_exploited``, ``ransomware_used``, ``kev_date``. EPSS auto-update
    writes to the existing EPSS fields in place. KEV sync writes the existing
    KEV/ransomware fields positively and keeps an app-owned audit snapshot of
    what this library discovered.
  * Finding has ``cve`` (CharField max 50, can hold non-CVE identifiers per
    its docstring) **plus** a ``Vulnerability_Id`` related model (one Finding
    -> many Vulnerability_Id rows). The CVE extractor inspects both.
  * Finding's ``DEDUPLICATION_FIELDS`` does NOT include ``epss_score`` or
    ``epss_percentile``, so writing them never affects deduplication.
"""

from __future__ import annotations

from decimal import Decimal

from django.conf import settings as django_settings
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from . import app_settings


# ---------------------------------------------------------------------------
# Enums (DRY: also used by templates and views)
# ---------------------------------------------------------------------------
class EPSSStatus(models.TextChoices):
    """Per-Finding enrichment status (req #12)."""

    NOT_CHECKED = "not_checked", _("not checked")
    MATCHED = "matched", _("matched")
    UPDATED = "updated", _("updated")
    SKIPPED = "skipped", _("skipped")
    FAILED = "failed", _("failed")


class EPSSAction(models.TextChoices):
    FETCH_RECENT = "fetch_recent", _("Fetch recent CVEs")
    FETCH_THRESHOLD = "fetch_threshold", _("Fetch CVEs by threshold")
    FETCH_SINGLE = "fetch_single", _("Fetch single CVE")
    FETCH_BATCH = "fetch_batch", _("Fetch CVE batch")
    DOWNLOAD_CSV = "download_csv", _("Download CSV")
    COMPARE = "compare", _("Compare against Findings")
    AUTO_UPDATE = "auto_update", _("Auto-update Findings")
    MANUAL_UPDATE = "manual_update", _("Manual update")
    KEV_SYNC = "kev_sync", _("KEV sync")


class EPSSLogStatus(models.TextChoices):
    STARTED = "started", _("started")
    SUCCESS = "success", _("success")
    PARTIAL_SUCCESS = "partial_success", _("partial success")
    FAILED = "failed", _("failed")
    SKIPPED = "skipped", _("skipped")


class EPSSSource(models.TextChoices):
    FIRST_API = "first.org", _("FIRST.org REST API")
    FIRST_CSV = "first.org-csv", _("FIRST.org daily CSV")
    MANUAL = "manual", _("Manual upload")


class KEVSourceType(models.TextChoices):
    JSON = "json", _("API / JSON feed")
    CSV = "csv", _("CSV feed")


class EPSSSeverity(models.TextChoices):
    """Mirror of DefectDojo's standard severity vocabulary."""

    INFO = "Info", _("Info")
    LOW = "Low", _("Low")
    MEDIUM = "Medium", _("Medium")
    HIGH = "High", _("High")
    CRITICAL = "Critical", _("Critical")


# ===========================================================================
# 1) EPSSSettings — singleton (PK=1)
# ===========================================================================
class EPSSSettings(models.Model):
    """Admin-editable runtime configuration for the EPSS module.

    Loaded with ``EPSSSettings.load()``; edited from the /epss/settings/
    page by superusers.
    """

    SINGLETON_ID = 1

    # ---- master switches (req #5, #6, #7, #9) -----------------------------
    enabled = models.BooleanField(
        default=False,
        help_text=_("Master switch for the EPSS module. When False, all "
                    "scheduled tasks short-circuit and write a 'skipped' log."),
    )
    fetch_recent_enabled = models.BooleanField(
        default=True,
        help_text=_("Allow fetching the most recent CVEs from FIRST.org."),
    )
    download_full_csv_enabled = models.BooleanField(
        default=False,
        help_text=_(
            "Allow downloading the full daily FIRST.org EPSS CSV from the URL "
            "configured in 'CSV base URL' below. Off by default — most "
            "deployments only need the REST API path. Turn on if you want "
            "bulk ingestion of all ~250k CVEs in one shot, or if you mirror "
            "EPSS internally and prefer pulling the daily snapshot."
        ),
    )
    compare_against_findings_enabled = models.BooleanField(
        default=True,
        help_text=_("Compare downloaded CVEs against existing Findings and "
                    "write match logs."),
    )
    auto_update_enabled = models.BooleanField(
        default=False,
        help_text=_("When True, matched Findings have their epss_score and "
                    "epss_percentile updated in place subject to scope filters."),
    )
    auto_chain_after_fetch = models.BooleanField(
        default=False,
        help_text=_(
            "When True, the 'Manual Fetch from FIRST.org' and 'Manual download CSV' "
            "buttons each run the full pipeline (fetch → compare → optionally "
            "auto-update) in one click. When False (default), fetch buttons only "
            "fetch EPSS data; the operator clicks the separate 'Compare' and "
            "'Auto-update' buttons to run those steps."
        ),
    )

    # ---- URLs (configurable per spec) -------------------------------------
    api_base_url = models.URLField(
        default=app_settings.DEFAULT_API_BASE_URL,
        help_text=_("Override to point at an internal mirror or proxy."),
    )
    csv_base_url = models.URLField(
        default=app_settings.DEFAULT_CSV_BASE_URL,
        help_text=_("Override to point at an internal CSV mirror."),
    )

    # ---- thresholds (req #2) ----------------------------------------------
    epss_score_threshold = models.DecimalField(
        max_digits=8, decimal_places=6,
        null=True, blank=True,
        validators=[MinValueValidator(Decimal("0.0")), MaxValueValidator(Decimal("1.0"))],
        help_text=_("Only fetch CVEs with EPSS score ≥ this value (0.0-1.0). "
                    "Blank = no threshold."),
    )
    epss_percentile_threshold = models.DecimalField(
        max_digits=8, decimal_places=6,
        null=True, blank=True,
        validators=[MinValueValidator(Decimal("0.0")), MaxValueValidator(Decimal("1.0"))],
        help_text=_("Only fetch CVEs with EPSS percentile ≥ this value. Blank = no threshold."),
    )
    fetch_date = models.DateField(
        null=True, blank=True,
        help_text=_("Optional: pin queries to a specific score date "
                    "(YYYY-MM-DD). Blank = today."),
    )
    result_limit = models.PositiveIntegerField(
        default=app_settings.DEFAULT_RESULT_LIMIT,
        help_text=_("Cap the number of rows pulled per fetch. The API client "
                    "paginates above this if needed."),
    )
    order_by_epss_desc = models.BooleanField(
        default=True,
        help_text=_("Sort API results by EPSS descending (highest risk first)."),
    )

    # ---- auto-update scope filters (req #10) ------------------------------
    update_active_findings_only = models.BooleanField(default=True)
    update_verified_findings_only = models.BooleanField(default=False)

    # JSONField is the simplest way to store a multi-select severity set
    # without coupling to DefectDojo's MultiSelectField.
    update_severities = models.JSONField(
        default=list, blank=True,
        help_text=_("List of severities eligible for auto-update "
                    "(e.g. ['Critical','High']). Empty = all severities."),
    )

    # Product / Product Type allowlists. We keep these as JSON lists of IDs to
    # avoid declaring a hard ManyToMany to dojo.Product (which would couple
    # our migrations). The matcher resolves IDs at query time.
    update_products = models.JSONField(
        default=list, blank=True,
        help_text=_("List of dojo Product IDs eligible for auto-update. "
                    "Empty = all products."),
    )
    update_product_types = models.JSONField(
        default=list, blank=True,
        help_text=_("List of dojo Product_Type IDs eligible for auto-update. "
                    "Empty = all product types."),
    )

    # Optional EPSS-range filter at update time (more restrictive than fetch).
    update_min_epss_score = models.DecimalField(
        max_digits=8, decimal_places=6,
        default=Decimal("0.000000"),
        validators=[MinValueValidator(Decimal("0.0")), MaxValueValidator(Decimal("1.0"))],
    )
    update_max_epss_score = models.DecimalField(
        max_digits=8, decimal_places=6,
        default=Decimal("1.000000"),
        validators=[MinValueValidator(Decimal("0.0")), MaxValueValidator(Decimal("1.0"))],
    )
    update_min_percentile = models.DecimalField(
        max_digits=8, decimal_places=6,
        default=Decimal("0.000000"),
        validators=[MinValueValidator(Decimal("0.0")), MaxValueValidator(Decimal("1.0"))],
    )
    update_max_percentile = models.DecimalField(
        max_digits=8, decimal_places=6,
        default=Decimal("1.000000"),
        validators=[MinValueValidator(Decimal("0.0")), MaxValueValidator(Decimal("1.0"))],
    )

    # ---- scheduling -------------------------------------------------------
    schedule_enabled = models.BooleanField(
        default=False,
        help_text=_(
            "Gate for scheduled EPSS full syncs. Manual button clicks always "
            "still run. The static Celery beat entry only wakes the scheduler "
            "dispatcher; this toggle decides whether EPSS is due for work."
        ),
    )
    schedule_interval_hours = models.PositiveSmallIntegerField(
        default=24,
        choices=((12, _("Every 12 hours")), (24, _("Every 24 hours"))),
        help_text=_("EPSS scheduled sync interval used by the dispatcher."),
    )
    epss_last_scheduled_run_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("Last time the dispatcher attempted a scheduled EPSS sync."),
    )
    # ---- CISA KEV / Known Exploited Vulnerabilities ----------------------
    kev_enabled = models.BooleanField(
        default=False,
        help_text=_(
            "Enable Known Exploited Vulnerability checks. This uses the "
            "DefectDojo Finding fields known_exploited, ransomware_used, "
            "and kev_date; it does not store the full KEV feed."
        ),
    )
    kev_source_type = models.CharField(
        max_length=8,
        choices=KEVSourceType.choices,
        default=KEVSourceType.JSON,
        help_text=_("Select whether the configured KEV source URL returns JSON or CSV."),
    )
    kev_source_url = models.URLField(
        max_length=1024,
        default=app_settings.DEFAULT_KEV_JSON_URL,
        help_text=_(
            "KEV source URL. Defaults to CISA's JSON feed, but can point "
            "to a compatible internal mirror or custom CSV/JSON feed."
        ),
    )
    kev_update_findings_enabled = models.BooleanField(
        default=True,
        help_text=_(
            "When True, matched Findings are updated positively only: "
            "known_exploited and ransomware_used can become Yes, and kev_date "
            "is set once to the first date this library found the CVE in KEV. "
            "Existing Yes values and dates are never reset by a later scan."
        ),
    )
    kev_schedule_enabled = models.BooleanField(
        default=False,
        help_text=_(
            "Gate for scheduled KEV syncs. Manual KEV actions still run."
        ),
    )
    kev_schedule_interval_hours = models.PositiveSmallIntegerField(
        default=24,
        choices=((12, _("Every 12 hours")), (24, _("Every 24 hours"))),
        help_text=_("KEV scheduled sync interval used by the dispatcher."),
    )
    kev_last_scheduled_run_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("Last time the dispatcher attempted a scheduled KEV sync."),
    )
    # ---- HTTP knobs -------------------------------------------------------
    http_timeout_secs = models.PositiveIntegerField(
        default=app_settings.DEFAULT_HTTP_TIMEOUT_SECS,
    )
    http_retries = models.PositiveIntegerField(
        default=app_settings.DEFAULT_HTTP_RETRIES,
    )

    # ---- bookkeeping ------------------------------------------------------
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        django_settings.AUTH_USER_MODEL,
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )

    class Meta:
        verbose_name = _("EPSS settings")
        verbose_name_plural = _("EPSS settings")
        permissions = [
            ("run_epss_fetch", _("Can trigger an EPSS fetch / compare / update")),
            ("view_epss_dashboard", _("Can view the EPSS dashboard and logs")),
        ]

    def __str__(self) -> str:
        return "EPSS settings"

    # This function keeps one settings row. This function needs a save call.
    def save(self, *args, **kwargs):
        # Force singleton.
        self.pk = self.SINGLETON_ID
        return super().save(*args, **kwargs)

    # This function blocks deleting settings. This function needs no input.
    def delete(self, *args, **kwargs):  # pragma: no cover - defensive
        return None

    # This function validates EPSS source choice. This function needs model fields.
    def clean(self):
        super().clean()
        if not self.has_valid_fetch_source():
            raise ValidationError({
                "fetch_recent_enabled": _(
                    "Choose exactly one EPSS source: FIRST.org fetch or daily CSV download.",
                ),
                "download_full_csv_enabled": _(
                    "Choose exactly one EPSS source: FIRST.org fetch or daily CSV download.",
                ),
            })

    # This function loads singleton settings. This function needs the database.
    @classmethod
    def load(cls) -> "EPSSSettings":
        obj, _ = cls.objects.get_or_create(pk=cls.SINGLETON_ID)
        return obj

    # ---- convenience parsers ---------------------------------------------
    # This function returns selected severities. This function needs saved JSON data.
    def severities_list(self) -> list[str]:
        v = self.update_severities or []
        return [str(x).strip() for x in v if str(x).strip()]

    # This function returns product ids. This function needs saved JSON data.
    def product_id_list(self) -> list[int]:
        return _coerce_int_list(self.update_products)

    # This function returns product type ids. This function needs saved JSON data.
    def product_type_id_list(self) -> list[int]:
        return _coerce_int_list(self.update_product_types)

    # This function returns selected EPSS source. This function needs source toggles.
    def active_fetch_source(self) -> str:
        """Return the selected fetch source, or an invalid-state marker."""
        if self.fetch_recent_enabled and not self.download_full_csv_enabled:
            return "firstorg"
        if self.download_full_csv_enabled and not self.fetch_recent_enabled:
            return "csv"
        if self.fetch_recent_enabled and self.download_full_csv_enabled:
            return "invalid_both"
        return "invalid_none"

    # This function checks EPSS source state. This function needs source toggles.
    def has_valid_fetch_source(self) -> bool:
        return self.active_fetch_source() in {"firstorg", "csv"}

    # This function builds the CSV URL. This function needs an optional score date.
    def csv_url_for(self, score_date=None) -> str:
        """Return the CSV download URL.

        If ``score_date`` is None, returns the always-current pointer
        ('epss_scores-current.csv.gz') — the latest published snapshot,
        whatever its date. If a specific date is passed, builds the
        date-specific filename.
        """
        base = (self.csv_base_url or app_settings.DEFAULT_CSV_BASE_URL).rstrip("/")
        if score_date is None:
            fname = app_settings.DEFAULT_CSV_CURRENT_FILENAME
        else:
            fname = app_settings.DEFAULT_CSV_FILENAME_TEMPLATE.format(date=score_date.isoformat())
        return f"{base}/{fname}"


# This function converts values to ints. This function needs a list-like value.
def _coerce_int_list(value) -> list[int]:
    out: list[int] = []
    for raw in (value or []):
        try:
            out.append(int(raw))
        except (TypeError, ValueError):
            continue
    return out


# ===========================================================================
# 2) EPSSCVERecord — one row per CVE per score-date per source
# ===========================================================================
class EPSSCVERecord(models.Model):
    cve_id = models.CharField(max_length=32, db_index=True)
    epss_score = models.DecimalField(
        max_digits=8, decimal_places=6,
        validators=[MinValueValidator(Decimal("0.0")), MaxValueValidator(Decimal("1.0"))],
    )
    epss_percentile = models.DecimalField(
        max_digits=8, decimal_places=6,
        validators=[MinValueValidator(Decimal("0.0")), MaxValueValidator(Decimal("1.0"))],
    )
    epss_date = models.DateField(db_index=True)
    source = models.CharField(
        max_length=32,
        default=EPSSSource.FIRST_API,
        choices=EPSSSource.choices,
    )
    raw_data = models.JSONField(default=dict, blank=True)
    matched_findings_count = models.PositiveIntegerField(default=0)
    last_compared_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("EPSS CVE record")
        verbose_name_plural = _("EPSS CVE records")
        constraints = [
            models.UniqueConstraint(
                fields=["cve_id", "epss_date", "source"],
                name="dojo_epss_uniq_cve_date_src",
            ),
        ]
        indexes = [
            models.Index(fields=["-epss_date", "-epss_score"], name="epss_recent_top_idx"),
            models.Index(fields=["-epss_score"], name="epss_score_desc_idx"),
            models.Index(fields=["-epss_percentile"], name="epss_pctile_desc_idx"),
        ]
        ordering = ["-epss_date", "-epss_score"]

    def __str__(self) -> str:
        return f"{self.cve_id}@{self.epss_date} epss={self.epss_score}"


# ===========================================================================
# 3) FindingEPSSUpdate — OneToOne to dojo.Finding (per the spec)
# ===========================================================================
class FindingEPSSUpdate(models.Model):
    finding = models.OneToOneField(
        f"{app_settings.DOJO_APP_LABEL}.Finding",
        on_delete=models.CASCADE,
        related_name="epss_update",
    )

    # Snapshot of the CVE we matched on (for display + audit). Stored as a
    # plain CharField — a Finding may have multiple CVEs; the matcher picks
    # the one with the highest EPSS score and stores all considered ones in
    # the corresponding EPSSUpdateLog.details.
    cve_id = models.CharField(max_length=32, db_index=True, blank=True, default="")

    epss_score = models.DecimalField(
        max_digits=8, decimal_places=6, null=True, blank=True,
        validators=[MinValueValidator(Decimal("0.0")), MaxValueValidator(Decimal("1.0"))],
    )
    epss_percentile = models.DecimalField(
        max_digits=8, decimal_places=6, null=True, blank=True,
        validators=[MinValueValidator(Decimal("0.0")), MaxValueValidator(Decimal("1.0"))],
    )
    epss_date = models.DateField(null=True, blank=True)

    status = models.CharField(
        max_length=16,
        choices=EPSSStatus.choices,
        default=EPSSStatus.NOT_CHECKED,
    )
    reason = models.TextField(blank=True, default="")

    last_checked_at = models.DateTimeField(null=True, blank=True)
    last_updated_at = models.DateTimeField(null=True, blank=True)

    source_record = models.ForeignKey(
        EPSSCVERecord,
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="finding_updates",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("Finding EPSS update")
        verbose_name_plural = _("Finding EPSS updates")
        indexes = [
            models.Index(fields=["status"], name="epss_fu_status_idx"),
            models.Index(fields=["-last_updated_at"], name="epss_fu_last_upd_idx"),
            models.Index(fields=["cve_id"], name="epss_fu_cve_idx"),
        ]

    def __str__(self) -> str:
        return f"FindingEPSSUpdate finding={self.finding_id} cve={self.cve_id} status={self.status}"


# ===========================================================================
# 4) FindingKEVUpdate — OneToOne to dojo.Finding
# ===========================================================================
class FindingKEVUpdate(models.Model):
    finding = models.OneToOneField(
        f"{app_settings.DOJO_APP_LABEL}.Finding",
        on_delete=models.CASCADE,
        related_name="kev_update",
    )

    cve_id = models.CharField(max_length=32, db_index=True, blank=True, default="")
    known_exploited = models.BooleanField(default=False)
    ransomware_used = models.BooleanField(default=False)

    # Local first-found dates. These are intentionally not overwritten by
    # later scans once set.
    kev_found_date = models.DateField(null=True, blank=True)
    ransomware_found_date = models.DateField(null=True, blank=True)

    status = models.CharField(
        max_length=16,
        choices=EPSSStatus.choices,
        default=EPSSStatus.NOT_CHECKED,
    )
    reason = models.TextField(blank=True, default="")

    source_type = models.CharField(
        max_length=8,
        choices=KEVSourceType.choices,
        default=KEVSourceType.JSON,
    )
    source_url = models.URLField(max_length=1024, blank=True, default="")
    raw_data = models.JSONField(default=dict, blank=True)

    last_checked_at = models.DateTimeField(null=True, blank=True)
    last_updated_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("Finding KEV update")
        verbose_name_plural = _("Finding KEV updates")
        indexes = [
            models.Index(fields=["status"], name="kev_fu_status_idx"),
            models.Index(fields=["cve_id"], name="kev_fu_cve_idx"),
            models.Index(fields=["kev_found_date"], name="kev_fu_found_idx"),
            models.Index(fields=["-last_updated_at"], name="kev_fu_last_upd_idx"),
        ]

    def __str__(self) -> str:
        return f"FindingKEVUpdate finding={self.finding_id} cve={self.cve_id} status={self.status}"


# ===========================================================================
# 5) EPSSUpdateLog — audit row for every action
# ===========================================================================
class EPSSUpdateLog(models.Model):
    action = models.CharField(max_length=32, choices=EPSSAction.choices, db_index=True)
    status = models.CharField(
        max_length=20,
        choices=EPSSLogStatus.choices,
        default=EPSSLogStatus.STARTED,
        db_index=True,
    )

    requested_by = models.ForeignKey(
        django_settings.AUTH_USER_MODEL,
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )

    started_at = models.DateTimeField(default=timezone.now, db_index=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    total_cves_fetched = models.PositiveIntegerField(default=0)
    total_cves_saved = models.PositiveIntegerField(default=0)
    total_findings_scanned = models.PositiveIntegerField(default=0)
    total_matches = models.PositiveIntegerField(default=0)
    total_findings_updated = models.PositiveIntegerField(default=0)
    total_skipped = models.PositiveIntegerField(default=0)
    total_failed = models.PositiveIntegerField(default=0)

    request_params = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True, default="")
    details = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = _("EPSS update log")
        verbose_name_plural = _("EPSS update logs")
        ordering = ["-started_at"]

    def __str__(self) -> str:
        return f"EPSSUpdateLog#{self.pk} action={self.action} status={self.status}"

    def mark_finished(
        self,
        status: str = EPSSLogStatus.SUCCESS,
        error: str = "",
    ) -> None:
        self.finished_at = timezone.now()
        self.status = status
        if error:
            # Cap error_message to a sane size.
            self.error_message = error[:8000]
        self.save(update_fields=[
            "finished_at", "status", "error_message",
            "total_cves_fetched", "total_cves_saved", "total_findings_scanned",
            "total_matches", "total_findings_updated", "total_skipped",
            "total_failed", "request_params", "details",
        ])


# ===========================================================================
# 6) EPSSDownloadBatch — one row per CSV download
# ===========================================================================
class EPSSDownloadBatch(models.Model):
    epss_date = models.DateField(db_index=True)
    source_url = models.URLField(max_length=512)
    local_file_path = models.CharField(
        max_length=1024, blank=True, default="",
        help_text=_("Absolute path on disk if the CSV was persisted; "
                    "empty when streaming-parsed only."),
    )
    checksum = models.CharField(
        max_length=128, blank=True, default="",
        help_text=_("Optional SHA-256 of the downloaded file."),
    )
    status = models.CharField(
        max_length=20,
        choices=EPSSLogStatus.choices,
        default=EPSSLogStatus.STARTED,
    )
    records_processed = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)

    log = models.ForeignKey(
        EPSSUpdateLog,
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="download_batches",
    )

    class Meta:
        verbose_name = _("EPSS download batch")
        verbose_name_plural = _("EPSS download batches")
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"EPSSDownloadBatch#{self.pk} {self.epss_date} {self.status}"
