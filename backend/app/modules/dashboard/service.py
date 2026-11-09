import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import NotFoundException
from app.modules.auth import User, UserRole
from app.modules.assessments import AssessmentService
from app.modules.targets import TargetService
from app.modules.findings import FindingService, FindingSeverity, FindingStatus
from app.modules.recon import ReconService
from app.modules.scans import ScanService
from app.modules.ai_analysis import AIAnalysisService
from app.modules.audit import AuditService
from app.modules.reporting import ReportingService
from app.modules.dashboard.schemas import (
    AssessmentDashboardResponse,
    AssessmentMetadata,
    ScopeCounts,
    FindingDashboardSummary,
    TopFindingItem,
    AssetDashboardSummary,
    ScanDashboardSummary,
    AIDashboardSummary,
    ActivityDashboardItem,
    LatestReportMetadata,
    GlobalDashboardResponse,
    AssessmentOverviewItem,
    DashboardMetrics,
    SeverityCount,
)

ALL_SEVERITIES = ["critical", "high", "medium", "low", "info"]
ALL_STATUSES = ["unverified", "confirmed", "false_positive", "needs_testing"]


class DashboardService:
    """Public business logic service for read-only dashboard aggregations."""

    def __init__(self, db: Session):
        self.db = db
        self.assessment_service = AssessmentService(db)
        self.target_service = TargetService(db)
        self.finding_service = FindingService(db)
        self.recon_service = ReconService(db)
        self.scan_service = ScanService(db)
        self.ai_service = AIAnalysisService(db)
        self.audit_service = AuditService(db)
        self.reporting_service = ReportingService(db)

    def get_assessment_dashboard(
        self,
        assessment_id: uuid.UUID,
        user: User,
    ) -> AssessmentDashboardResponse:
        """Fetch consolidated dashboard data for a single assessment."""
        assessment = self.assessment_service.get_assessment(assessment_id)
        if not assessment:
            raise NotFoundException("Assessment", assessment_id)

        target = self.target_service.get_target(assessment.target_id)
        target_name = target.name if target else None
        target_base_url = target.base_url if target else None

        # 1. Scope counts
        scope_items = self.target_service.list_scope_items(assessment.target_id)
        in_scope_count = sum(1 for item in scope_items if item.in_scope)
        out_of_scope_count = sum(1 for item in scope_items if not item.in_scope)
        scope_counts = ScopeCounts(
            in_scope=in_scope_count,
            out_of_scope=out_of_scope_count,
            total=len(scope_items),
        )

        # 2. Findings summary
        f_summary = self.finding_service.get_findings_summary(assessment_id)
        by_sev = {s: f_summary.by_severity.get(s, 0) for s in ALL_SEVERITIES}
        conf_by_sev = {s: f_summary.confirmed_by_effective_severity.get(s, 0) for s in ALL_SEVERITIES}
        by_stat = {st: f_summary.by_status.get(st, 0) for st in ALL_STATUSES}
        conf_by_cat = f_summary.confirmed_by_category or {}

        findings_dashboard = FindingDashboardSummary(
            total=f_summary.total,
            by_status=by_stat,
            by_severity=by_sev,
            confirmed_by_effective_severity=conf_by_sev,
            confirmed_by_category=conf_by_cat,
            verification_progress=f_summary.verification_progress,
            unverified_count=f_summary.unverified_count,
            verified_count=f_summary.verified_count,
        )

        # 3. Top findings
        top_raw = self.finding_service.get_top_findings(assessment_id, limit=settings.DASHBOARD_TOP_FINDINGS)
        top_findings = [
            TopFindingItem(
                id=tf.id,
                title=tf.title,
                severity=tf.effective_severity.value if hasattr(tf.effective_severity, "value") else str(tf.effective_severity),
                category=tf.category,
            )
            for tf in top_raw
        ]

        # 4. Assets summary
        asset_summary = self.recon_service.get_asset_summary(assessment_id)
        assets_dashboard = AssetDashboardSummary(
            total=asset_summary.get("total", 0),
            by_type=asset_summary.get("by_type", {}),
            open_ports_and_services=asset_summary.get("open_ports_and_services", []),
        )

        # 5. Scans summary
        scans_summary = self.scan_service.get_scans_summary(assessment_id)
        scans_dashboard = ScanDashboardSummary(
            total=scans_summary.get("total", 0),
            by_tool=scans_summary.get("by_tool", {}),
            by_status=scans_summary.get("by_status", {}),
            last_scan_at=scans_summary.get("last_scan_at"),
            recent_scans=[
                {
                    "id": str(s.id),
                    "tool": s.tool.value if hasattr(s.tool, "value") else str(s.tool),
                    "status": s.status.value if hasattr(s.status, "value") else str(s.status),
                    "command": s.command,
                    "started_at": s.started_at.isoformat() if s.started_at else None,
                    "finished_at": s.finished_at.isoformat() if s.finished_at else None,
                }
                for s in scans_summary.get("recent_scans", [])
            ],
        )

        # 6. AI summary
        ai_summary = self.ai_service.get_ai_dashboard_summary(assessment_id)
        ai_dashboard = AIDashboardSummary(
            total=ai_summary.get("total", 0),
            by_function=ai_summary.get("by_function", {}),
            by_status=ai_summary.get("by_status", {}),
            approved_count=ai_summary.get("approved_count", 0),
            has_approved_executive_summary=ai_summary.get("has_approved_executive_summary", False),
            ai_promoted_findings_count=ai_summary.get("ai_promoted_findings_count", 0),
            ai_promoted_confirmed_count=ai_summary.get("ai_promoted_confirmed_count", 0),
        )

        # 7. Recent activity (Audit)
        is_admin = (user.role == UserRole.ADMIN or getattr(user.role, "value", str(user.role)) == "admin")
        activity_logs = self.audit_service.list_assessment_activity(
            assessment_id=assessment_id,
            limit=settings.DASHBOARD_RECENT_ACTIVITY,
            is_admin=is_admin,
        )
        recent_activity = [
            ActivityDashboardItem(
                id=a.id,
                action=a.action,
                created_at=a.created_at,
                user_id=a.user_id,
                detail=a.detail,
            )
            for a in activity_logs
        ]

        # 8. Latest report
        latest_report = self.reporting_service.get_latest_report(assessment_id)
        latest_report_meta = None
        if latest_report:
            latest_report_meta = LatestReportMetadata(
                id=latest_report.id,
                version=latest_report.version,
                format=latest_report.format,
                status=latest_report.status,
                generated_at=latest_report.generated_at,
                sha256=latest_report.sha256,
                size_bytes=latest_report.size_bytes,
            )

        return AssessmentDashboardResponse(
            assessment=AssessmentMetadata(
                id=assessment.id,
                name=assessment.name,
                target_id=assessment.target_id,
                target_name=target_name,
                target_base_url=target_base_url,
                status=assessment.status.value if hasattr(assessment.status, "value") else str(assessment.status),
                created_at=assessment.created_at,
                updated_at=getattr(assessment, "updated_at", None),
            ),
            scope=scope_counts,
            findings=findings_dashboard,
            top_findings=top_findings,
            assets=assets_dashboard,
            scans=scans_dashboard,
            ai=ai_dashboard,
            recent_activity=recent_activity,
            reports=latest_report_meta,
            generated_at=datetime.now(timezone.utc),
        )

    def get_global_dashboard(
        self,
        limit: int = 50,
        offset: int = 0,
        user: Optional[User] = None,
    ) -> GlobalDashboardResponse:
        """Fetch global counts and paginated assessment overview list."""
        assessments_list = self.assessment_service.list_assessments(limit=limit, offset=offset)
        total_assessments = len(self.assessment_service.list_assessments(limit=1000, offset=0))
        total_targets = len(self.target_service.list_targets(limit=1000, offset=0))

        # Global findings and scan aggregates
        global_by_severity = {s: 0 for s in ALL_SEVERITIES}
        global_by_status = {st: 0 for st in ALL_STATUSES}
        total_findings = 0
        total_scans = 0

        overview_items: List[AssessmentOverviewItem] = []
        for a in assessments_list:
            t = self.target_service.get_target(a.target_id)
            f_summary = self.finding_service.get_findings_summary(a.id)
            scans = self.scan_service.list_scans_for_assessment(a.id)
            total_scans += len(scans)

            total_findings += f_summary.total
            for s, c in f_summary.by_severity.items():
                if s in global_by_severity:
                    global_by_severity[s] += c
            for st, c in f_summary.by_status.items():
                if st in global_by_status:
                    global_by_status[st] += c

            conf_count = f_summary.by_status.get("confirmed", 0)

            overview_items.append(
                AssessmentOverviewItem(
                    id=a.id,
                    name=a.name,
                    target_name=t.name if t else None,
                    status=a.status.value if hasattr(a.status, "value") else str(a.status),
                    created_at=a.created_at,
                    total_findings=f_summary.total,
                    confirmed_findings=conf_count,
                    verification_progress=f_summary.verification_progress,
                )
            )

        return GlobalDashboardResponse(
            total_assessments=total_assessments,
            total_targets=total_targets,
            total_scans=total_scans,
            total_findings=total_findings,
            findings_by_severity=global_by_severity,
            findings_by_status=global_by_status,
            assessments=overview_items,
            pagination={
                "limit": limit,
                "offset": offset,
                "total": total_assessments,
            },
            generated_at=datetime.now(timezone.utc),
        )

    def get_metrics(self) -> DashboardMetrics:
        """Backwards compatibility metrics endpoint."""
        gd = self.get_global_dashboard(limit=10, offset=0)
        return DashboardMetrics(
            total_targets=gd.total_targets,
            total_assessments=gd.total_assessments,
            total_scans=gd.total_scans,
            total_findings=gd.total_findings,
            findings_by_severity=[
                SeverityCount(severity=s, count=c)
                for s, c in gd.findings_by_severity.items()
            ],
            findings_by_status=gd.findings_by_status,
        )
