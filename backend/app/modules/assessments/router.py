import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user, require_roles
from app.core.exceptions import NotFoundException
from app.modules.auth import User
from app.modules.assessments.schemas import AssessmentCreate, AssessmentRead
from app.modules.assessments.service import AssessmentService
from app.modules.scans import ScanService, ScanCreate, ScanRead
from app.modules.recon import ReconService
from app.modules.recon.schemas import AssetRead
from app.modules.web_assessment import WebAssessmentService, WebAssessmentRequest
from app.modules.findings import (
    FindingService,
    FindingRead,
    FindingsSummary,
    FindingSeverity,
    FindingStatus,
    FindingSource,
)

router = APIRouter(prefix="/assessments", tags=["assessments"])


@router.post("", response_model=AssessmentRead, status_code=status.HTTP_201_CREATED)
@router.post("/", response_model=AssessmentRead, status_code=status.HTTP_201_CREATED, include_in_schema=False)
def create_assessment(
    assessment_in: AssessmentCreate,
    current_user: User = Depends(require_roles("assessor", "admin")),
    db: Session = Depends(get_db),
) -> AssessmentRead:
    """Register a new assessment cycle associated with a target."""
    service = AssessmentService(db)
    return service.create_assessment(assessment_in, user_id=current_user.id)


@router.get("", response_model=List[AssessmentRead], status_code=status.HTTP_200_OK)
@router.get("/", response_model=List[AssessmentRead], status_code=status.HTTP_200_OK, include_in_schema=False)
def list_assessments(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[AssessmentRead]:
    """List all registered assessments."""
    service = AssessmentService(db)
    return service.list_assessments(limit=limit, offset=offset)


@router.get("/{assessment_id}", response_model=AssessmentRead, status_code=status.HTTP_200_OK)
def get_assessment(
    assessment_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AssessmentRead:
    """Retrieve details of a specific assessment."""
    service = AssessmentService(db)
    assessment = service.get_assessment(assessment_id)
    if not assessment:
        raise NotFoundException(resource="Assessment", identifier=assessment_id)
    return assessment


@router.post("/{assessment_id}/scans", response_model=ScanRead, status_code=status.HTTP_202_ACCEPTED)
def trigger_assessment_scan(
    assessment_id: uuid.UUID,
    scan_in: ScanCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_roles("assessor", "admin")),
    db: Session = Depends(get_db),
) -> ScanRead:
    """
    Trigger a reconnaissance or security scan for the assessment.
    Validates scope before enqueuing execution.
    Returns 202 Accepted with pending status, or 403 Forbidden if target is out of scope.
    """
    scan_service = ScanService(db)
    try:
        return scan_service.trigger_scan(
            assessment_id=assessment_id,
            scan_in=scan_in,
            background_tasks=background_tasks,
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(ve),
        )


@router.get("/{assessment_id}/scans", response_model=List[ScanRead], status_code=status.HTTP_200_OK)
def list_assessment_scans(
    assessment_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[ScanRead]:
    """List all scans triggered for an assessment."""
    assessment_service = AssessmentService(db)
    assessment = assessment_service.get_assessment(assessment_id)
    if not assessment:
        raise NotFoundException(resource="Assessment", identifier=assessment_id)

    scan_service = ScanService(db)
    return scan_service.list_scans_for_assessment(assessment_id)


@router.get("/{assessment_id}/scans/{scan_id}", response_model=ScanRead, status_code=status.HTTP_200_OK)
def get_assessment_scan_detail(
    assessment_id: uuid.UUID,
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScanRead:
    """Retrieve scan status and raw output."""
    assessment_service = AssessmentService(db)
    assessment = assessment_service.get_assessment(assessment_id)
    if not assessment:
        raise NotFoundException(resource="Assessment", identifier=assessment_id)

    scan_service = ScanService(db)
    scan = scan_service.get_scan(scan_id)
    if not scan or scan.assessment_id != assessment_id:
        raise NotFoundException(resource="Scan", identifier=scan_id)
    return scan


@router.get("/{assessment_id}/assets", response_model=List[AssetRead], status_code=status.HTTP_200_OK)
def list_assessment_assets(
    assessment_id: uuid.UUID,
    type: Optional[str] = Query(default=None, description="Filter by asset type (host/port/service/endpoint)"),
    scan_id: Optional[uuid.UUID] = Query(default=None, description="Filter by scan execution ID"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[AssetRead]:
    """List discovered assets for an assessment with optional filtering."""
    assessment_service = AssessmentService(db)
    assessment = assessment_service.get_assessment(assessment_id)
    if not assessment:
        raise NotFoundException(resource="Assessment", identifier=assessment_id)

    recon_service = ReconService(db)
    return recon_service.list_assets(
        assessment_id=assessment_id,
        asset_type=type,
        scan_id=scan_id,
    )


@router.post("/{assessment_id}/web-assessment", response_model=ScanRead, status_code=status.HTTP_202_ACCEPTED)
def trigger_web_assessment(
    assessment_id: uuid.UUID,
    request: WebAssessmentRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_roles("assessor", "admin")),
    db: Session = Depends(get_db),
) -> ScanRead:
    """
    Trigger a Web Application Security Assessment for the assessment.
    Validates scope and option allow-lists, returns 202 Accepted with pending scan row.
    Returns 422 for invalid categories/options, 403 if target base URL is out of scope.
    """
    service = WebAssessmentService(db)
    try:
        return service.trigger_web_assessment(
            assessment_id=assessment_id,
            request=request,
            background_tasks=background_tasks,
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(ve),
        )


@router.get("/{assessment_id}/findings", response_model=List[FindingRead], status_code=status.HTTP_200_OK)
def list_assessment_findings(
    assessment_id: uuid.UUID,
    category: Optional[str] = Query(default=None, description="Filter by finding category"),
    severity: Optional[FindingSeverity] = Query(default=None, description="Filter by original severity"),
    effective_severity: Optional[FindingSeverity] = Query(default=None, description="Filter by effective severity"),
    finding_status: Optional[FindingStatus] = Query(default=None, alias="status", description="Filter by status"),
    source: Optional[FindingSource] = Query(default=None, description="Filter by source (tool/ai)"),
    scan_id: Optional[uuid.UUID] = Query(default=None, description="Filter by scan ID"),
    verified_by: Optional[uuid.UUID] = Query(default=None, description="Filter by verifying assessor UUID"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[FindingRead]:
    """List findings for an assessment with optional filtering and pagination."""
    assessment_service = AssessmentService(db)
    assessment = assessment_service.get_assessment(assessment_id)
    if not assessment:
        raise NotFoundException(resource="Assessment", identifier=assessment_id)

    finding_service = FindingService(db)
    return finding_service.list_findings(
        assessment_id=assessment_id,
        category=category,
        severity=severity,
        effective_severity=effective_severity,
        status=finding_status,
        source=source,
        scan_id=scan_id,
        verified_by=verified_by,
        limit=limit,
        offset=offset,
    )


@router.get("/{assessment_id}/findings/summary", response_model=FindingsSummary, status_code=status.HTTP_200_OK)
def get_assessment_findings_summary(
    assessment_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> FindingsSummary:
    """Retrieve aggregated finding counts by severity, category, status, and confirmed effective severity."""
    assessment_service = AssessmentService(db)
    assessment = assessment_service.get_assessment(assessment_id)
    if not assessment:
        raise NotFoundException(resource="Assessment", identifier=assessment_id)

    finding_service = FindingService(db)
    return finding_service.get_findings_summary(assessment_id)


@router.get("/{assessment_id}/findings/export", status_code=status.HTTP_200_OK)
def export_assessment_findings(
    assessment_id: uuid.UUID,
    format: str = Query(default="csv", description="Export format: csv or json"),
    status: str = Query(default="confirmed", description="Filter by status: confirmed, unverified, false_positive, needs_testing, or all"),
    current_user: User = Depends(require_roles("assessor", "admin")),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    """Stream findings export with CSV injection protection and audit logging."""
    assessment_service = AssessmentService(db)
    assessment = assessment_service.get_assessment(assessment_id)
    if not assessment:
        raise NotFoundException(resource="Assessment", identifier=assessment_id)

    service = FindingService(db)
    generator, media_type, filename = service.prepare_findings_export(
        assessment_id=assessment_id,
        format_type=format,
        status_filter=status,
        user=current_user,
    )
    return StreamingResponse(
        content=generator,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/{assessment_id}/findings/{finding_id}", response_model=FindingRead, status_code=status.HTTP_200_OK)
def get_assessment_finding_detail(
    assessment_id: uuid.UUID,
    finding_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> FindingRead:
    """Retrieve details of a specific finding belonging to an assessment, including attached evidence."""
    assessment_service = AssessmentService(db)
    assessment = assessment_service.get_assessment(assessment_id)
    if not assessment:
        raise NotFoundException(resource="Assessment", identifier=assessment_id)

    finding_service = FindingService(db)
    finding = finding_service.get_finding(finding_id)
    if not finding or finding.assessment_id != assessment_id:
        raise NotFoundException(resource="Finding", identifier=finding_id)
    return finding
