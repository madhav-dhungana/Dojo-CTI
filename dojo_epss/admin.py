"""Django admin registration for dojo_epss models."""

from django.contrib import admin

from .models import (
    EPSSCVERecord,
    EPSSDownloadBatch,
    EPSSSettings,
    EPSSUpdateLog,
    FindingEPSSUpdate,
    FindingKEVUpdate,
)


@admin.register(EPSSSettings)
class EPSSSettingsAdmin(admin.ModelAdmin):
    list_display = ("__str__", "enabled", "fetch_recent_enabled",
                    "download_full_csv_enabled", "compare_against_findings_enabled",
                    "auto_update_enabled", "kev_enabled", "updated_at")

    def has_add_permission(self, request):
        return not EPSSSettings.objects.exists()

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(EPSSCVERecord)
class EPSSCVERecordAdmin(admin.ModelAdmin):
    list_display = ("cve_id", "epss_score", "epss_percentile", "epss_date",
                    "source", "matched_findings_count", "last_compared_at")
    list_filter = ("source", "epss_date")
    search_fields = ("cve_id",)
    readonly_fields = ("created_at", "updated_at", "matched_findings_count",
                       "last_compared_at")


@admin.register(FindingEPSSUpdate)
class FindingEPSSUpdateAdmin(admin.ModelAdmin):
    list_display = ("id", "finding_id", "cve_id", "status",
                    "epss_score", "epss_percentile", "last_updated_at")
    list_filter = ("status",)
    search_fields = ("cve_id",)
    autocomplete_fields = []  # let dojo's admin manage Finding lookups
    readonly_fields = ("finding", "source_record", "created_at", "updated_at",
                       "last_checked_at", "last_updated_at")


@admin.register(FindingKEVUpdate)
class FindingKEVUpdateAdmin(admin.ModelAdmin):
    list_display = ("id", "finding_id", "cve_id", "status",
                    "known_exploited", "ransomware_used",
                    "kev_found_date", "ransomware_found_date",
                    "last_updated_at")
    list_filter = ("status", "known_exploited", "ransomware_used", "source_type")
    search_fields = ("cve_id",)
    autocomplete_fields = []
    readonly_fields = tuple(f.name for f in FindingKEVUpdate._meta.fields)


@admin.register(EPSSUpdateLog)
class EPSSUpdateLogAdmin(admin.ModelAdmin):
    list_display = ("id", "action", "status", "started_at", "finished_at",
                    "total_cves_fetched", "total_cves_saved",
                    "total_findings_scanned", "total_matches",
                    "total_findings_updated", "total_skipped", "total_failed")
    list_filter = ("action", "status")
    readonly_fields = tuple(f.name for f in EPSSUpdateLog._meta.fields)


@admin.register(EPSSDownloadBatch)
class EPSSDownloadBatchAdmin(admin.ModelAdmin):
    list_display = ("id", "epss_date", "status", "records_processed",
                    "created_at", "processed_at")
    list_filter = ("status", "epss_date")
    readonly_fields = tuple(f.name for f in EPSSDownloadBatch._meta.fields)
