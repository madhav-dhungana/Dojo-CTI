"""API endpoints for dojo_epss."""

from __future__ import annotations

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import generics, serializers
from rest_framework.permissions import BasePermission, IsAuthenticated
from rest_framework.response import Response

from .models import EPSSStatus, FindingEPSSUpdate, FindingKEVUpdate


class DojoEpssDashboardPermission(BasePermission):
    """Allow staff, superusers, or users with the EPSS dashboard permission."""

    # This function checks API access. This function needs a request user.
    def has_permission(self, request, view) -> bool:  # noqa: ARG002
        user = request.user
        if not user or not user.is_authenticated:
            return False
        return (
            user.is_superuser
            or user.is_staff
            or user.has_perm("dojo_epss.view_epss_dashboard")
        )


class FindingKEVSnapshotSerializer(serializers.Serializer):
    """KEV data attached to one finding match."""

    cve_id = serializers.CharField(allow_blank=True)
    known_exploited = serializers.BooleanField()
    ransomware_used = serializers.BooleanField()
    kev_found_date = serializers.DateField(allow_null=True)
    ransomware_found_date = serializers.DateField(allow_null=True)
    status = serializers.CharField()
    reason = serializers.CharField(allow_blank=True)
    last_checked_at = serializers.DateTimeField(allow_null=True)
    last_updated_at = serializers.DateTimeField(allow_null=True)


class FindingEPSSMatchSerializer(serializers.ModelSerializer):
    """EPSS and KEV match data for one DefectDojo Finding."""

    finding_id = serializers.IntegerField(read_only=True)
    finding_title = serializers.SerializerMethodField()
    source_record_id = serializers.IntegerField(read_only=True)
    kev = serializers.SerializerMethodField()

    class Meta:
        model = FindingEPSSUpdate
        fields = (
            "id",
            "finding_id",
            "finding_title",
            "cve_id",
            "epss_score",
            "epss_percentile",
            "epss_date",
            "status",
            "reason",
            "source_record_id",
            "kev",
            "last_checked_at",
            "last_updated_at",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields

    # This function returns the Finding title. This function needs a match row.
    def get_finding_title(self, obj) -> str:
        return str(getattr(obj.finding, "title", "") or "")

    # This function returns KEV data. This function needs a match row.
    def get_kev(self, obj) -> dict | None:
        kev = getattr(obj, "kev_snapshot", None)
        if kev is None:
            return None
        return FindingKEVSnapshotSerializer(kev).data


@extend_schema(
    tags=["dojo_epss"],
    summary="List EPSS finding matches",
    description=(
        "Returns Finding EPSS match rows created by the dojo_epss matcher. "
        "Each row includes the related KEV snapshot when one exists."
    ),
    parameters=[
        OpenApiParameter(
            "status",
            OpenApiTypes.STR,
            OpenApiParameter.QUERY,
            required=False,
            description="Filter by EPSS status, for example matched, updated, skipped, or failed.",
        ),
        OpenApiParameter(
            "finding_id",
            OpenApiTypes.INT,
            OpenApiParameter.QUERY,
            required=False,
            description="Filter to one DefectDojo Finding id.",
        ),
        OpenApiParameter(
            "cve_id",
            OpenApiTypes.STR,
            OpenApiParameter.QUERY,
            required=False,
            description="Filter by matched CVE id.",
        ),
        OpenApiParameter(
            "kev",
            OpenApiTypes.BOOL,
            OpenApiParameter.QUERY,
            required=False,
            description="When true, return only rows with known exploited KEV data.",
        ),
        OpenApiParameter(
            "ransomware",
            OpenApiTypes.BOOL,
            OpenApiParameter.QUERY,
            required=False,
            description="When true, return only rows with ransomware usage data.",
        ),
    ],
    responses={200: FindingEPSSMatchSerializer(many=True)},
)
class FindingEPSSMatchListAPIView(generics.ListAPIView):
    """Read-only API for the Finding Matches page."""

    serializer_class = FindingEPSSMatchSerializer
    permission_classes = (IsAuthenticated, DojoEpssDashboardPermission)

    # This function builds the match queryset. This function needs query parameters.
    def get_queryset(self):
        qs = (
            FindingEPSSUpdate.objects.exclude(status=EPSSStatus.NOT_CHECKED)
            .select_related("finding", "source_record")
            .order_by("-last_checked_at", "-id")
        )

        status = (self.request.query_params.get("status") or "").strip()
        if status:
            qs = qs.filter(status=status)

        finding_id = (self.request.query_params.get("finding_id") or "").strip()
        if finding_id.isdigit():
            qs = qs.filter(finding_id=int(finding_id))

        cve_id = (self.request.query_params.get("cve_id") or "").strip().upper()
        if cve_id:
            qs = qs.filter(cve_id=cve_id)

        if _truthy_query(self.request.query_params.get("kev")):
            qs = qs.filter(finding_id__in=_kev_finding_ids(known=True))
        if _truthy_query(self.request.query_params.get("ransomware")):
            qs = qs.filter(finding_id__in=_kev_finding_ids(ransomware=True))
        return qs

    # This function lists match rows. This function needs a request.
    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        if page is not None:
            self._attach_kev_snapshots(page)
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        rows = list(queryset)
        self._attach_kev_snapshots(rows)
        serializer = self.get_serializer(rows, many=True)
        return Response(serializer.data)

    # This function attaches KEV snapshots. This function needs match rows.
    def _attach_kev_snapshots(self, rows) -> None:
        ids = [row.finding_id for row in rows]
        kev_by_finding = {
            row.finding_id: row
            for row in FindingKEVUpdate.objects.filter(finding_id__in=ids)
        }
        for row in rows:
            row.kev_snapshot = kev_by_finding.get(row.finding_id)


# This function reads boolean query values. This function needs a raw value.
def _truthy_query(value) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "on"}


# This function finds KEV Finding ids. This function needs a KEV filter type.
def _kev_finding_ids(*, known: bool = False, ransomware: bool = False):
    qs = FindingKEVUpdate.objects.all()
    if known:
        qs = qs.filter(known_exploited=True)
    if ransomware:
        qs = qs.filter(ransomware_used=True)
    return qs.values_list("finding_id", flat=True)
