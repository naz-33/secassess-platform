import uuid
from datetime import datetime
from typing import List, Dict, Optional, Any
from pydantic import BaseModel


class SeverityCount(BaseModel):
    severity: str
    count: int


class DashboardMetrics(BaseModel):
    total_targets: int = 0
    total_assessments: int = 0
    total_scans: int = 0
    total_findings: int = 0
    findings_by_severity: List[SeverityCount] = []
    findings_by_status: Dict[str, int] = {}


class AssessmentMetadata(BaseModel):
    id: uuid.UUID
    name: str
    target_id: uuid.UUID
    target_name: Optional[str] = None
    target_base_url: Optional[str] = None
    status: str
    created_at: datetime
    updated_at: Optional[datetime] = None


class ScopeCounts(BaseModel):
    in_scope: int
    out_of_scope: int
    total: int


class FindingDashboardSummary(BaseModel):
    total: int
    by_status: Dict[str, int]
    by_severity: Dict[str, int]
    confirmed_by_effective_severity: Dict[str, int]
    confirmed_by_category: Dict[str, int]
    verification_progress: float
    unverified_count: int
    verified_count: int


class TopFindingItem(BaseModel):
    id: uuid.UUID
    title: str
    severity: str
    category: str


class AssetDashboardSummary(BaseModel):
    total: int
    by_type: Dict[str, int]
    open_ports_and_services: List[Dict[str, Any]]


class ScanDashboardSummary(BaseModel):
    total: int
    by_tool: Dict[str, int]
    by_status: Dict[str, int]
    last_scan_at: Optional[datetime] = None
    recent_scans: List[Dict[str, Any]]


class AIDashboardSummary(BaseModel):
    total: int
    by_function: Dict[str, int]
    by_status: Dict[str, int]
    approved_count: int
    has_approved_executive_summary: bool
    ai_promoted_findings_count: int
    ai_promoted_confirmed_count: int


class ActivityDashboardItem(BaseModel):
    id: uuid.UUID
    action: str
    created_at: datetime
    user_id: Optional[uuid.UUID] = None
    detail: Optional[str] = None


class LatestReportMetadata(BaseModel):
    id: uuid.UUID
    version: int
    format: str
    status: str
    generated_at: Optional[datetime] = None
    sha256: Optional[str] = None
    size_bytes: Optional[int] = None


class AssessmentDashboardResponse(BaseModel):
    assessment: AssessmentMetadata
    scope: ScopeCounts
    findings: FindingDashboardSummary
    top_findings: List[TopFindingItem]
    assets: AssetDashboardSummary
    scans: ScanDashboardSummary
    ai: AIDashboardSummary
    recent_activity: List[ActivityDashboardItem]
    reports: Optional[LatestReportMetadata] = None
    generated_at: datetime


class AssessmentOverviewItem(BaseModel):
    id: uuid.UUID
    name: str
    target_name: Optional[str] = None
    status: str
    created_at: datetime
    total_findings: int
    confirmed_findings: int
    verification_progress: float


class GlobalDashboardResponse(BaseModel):
    total_assessments: int
    total_targets: int
    total_scans: int
    total_findings: int
    findings_by_severity: Dict[str, int]
    findings_by_status: Dict[str, int]
    assessments: List[AssessmentOverviewItem]
    pagination: Dict[str, int]
    generated_at: datetime
