import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, UploadFile, File, Form, Query, status
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user, require_roles
from app.core.exceptions import NotFoundException
from app.modules.auth import User
from app.modules.findings.models import (
    FindingSeverity,
    FindingStatus,
    FindingSource,
)
from app.modules.findings.schemas import (
    FindingRead,
    EvidenceRead,
    SeverityUpdateRequest,
    SeverityChangeRead,
    NoteEvidenceCreate,
)
from app.modules.findings.service import FindingService

router = APIRouter(tags=["findings"])


@router.get("/findings", response_model=List[FindingRead], status_code=status.HTTP_200_OK)
def list_all_findings(
    assessment_id: Optional[uuid.UUID] = Query(default=None, description="Optional assessment ID filter"),
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
    """List findings across all assessments or filtered by assessment with optional filtering and pagination."""
    service = FindingService(db)
    return service.list_findings(
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


@router.get("/findings/{finding_id}", response_model=FindingRead, status_code=status.HTTP_200_OK)
def get_finding_by_id(
    finding_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> FindingRead:
    """Retrieve details of a specific finding including its attached evidence."""
    service = FindingService(db)
    finding = service.get_finding(finding_id)
    if not finding:
        raise NotFoundException(resource="Finding", identifier=finding_id)
    return finding


@router.patch("/findings/{finding_id}/severity", response_model=FindingRead, status_code=status.HTTP_200_OK)
def override_finding_severity(
    finding_id: uuid.UUID,
    override_in: SeverityUpdateRequest,
    current_user: User = Depends(require_roles("assessor", "admin")),
    db: Session = Depends(get_db),
) -> FindingRead:
    """Override a finding's severity with mandatory justification and CVSS updates."""
    service = FindingService(db)
    return service.override_severity(finding_id=finding_id, override_in=override_in, user=current_user)


@router.get("/findings/{finding_id}/severity-history", response_model=List[SeverityChangeRead], status_code=status.HTTP_200_OK)
def get_finding_severity_history(
    finding_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[SeverityChangeRead]:
    """Retrieve chronological history of severity adjustments."""
    service = FindingService(db)
    return service.list_severity_history(finding_id)


@router.get("/findings/{finding_id}/evidence", response_model=List[EvidenceRead], status_code=status.HTTP_200_OK)
def get_finding_evidence(
    finding_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[EvidenceRead]:
    """Retrieve all evidence records attached to a finding."""
    service = FindingService(db)
    finding = service.get_finding(finding_id)
    if not finding:
        raise NotFoundException(resource="Finding", identifier=finding_id)
    return service.list_evidence_for_finding(finding_id)


@router.post(
    "/findings/{finding_id}/evidence/upload",
    response_model=EvidenceRead,
    status_code=status.HTTP_201_CREATED,
)
async def upload_finding_evidence(
    finding_id: uuid.UUID,
    file: UploadFile = File(...),
    label: str = Form(...),
    notes: Optional[str] = Form(None),
    current_user: User = Depends(require_roles("assessor", "admin")),
    db: Session = Depends(get_db),
) -> EvidenceRead:
    """Upload manual evidence file with magic bytes validation and secure storage."""
    file_bytes = await file.read()
    service = FindingService(db)
    return service.upload_evidence(
        finding_id=finding_id,
        file_bytes=file_bytes,
        original_filename=file.filename or "upload.bin",
        label=label,
        notes=notes,
        user=current_user,
    )


@router.post(
    "/findings/{finding_id}/evidence/note",
    response_model=EvidenceRead,
    status_code=status.HTTP_201_CREATED,
)
def add_finding_note(
    finding_id: uuid.UUID,
    note_in: NoteEvidenceCreate,
    current_user: User = Depends(require_roles("assessor", "admin")),
    db: Session = Depends(get_db),
) -> EvidenceRead:
    """Attach plain text assessor notes as finding evidence."""
    service = FindingService(db)
    return service.add_note_evidence(finding_id=finding_id, note_in=note_in, user=current_user)


@router.get("/evidence/{evidence_id}", response_model=EvidenceRead, status_code=status.HTTP_200_OK)
def get_evidence_by_id(
    evidence_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> EvidenceRead:
    """Retrieve an immutable evidence artifact metadata by ID."""
    service = FindingService(db)
    evidence = service.get_evidence(evidence_id)
    if not evidence:
        raise NotFoundException(resource="Evidence", identifier=evidence_id)
    return evidence


@router.get("/evidence/{evidence_id}/download", status_code=status.HTTP_200_OK)
def download_evidence_file(
    evidence_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> FileResponse:
    """Download an evidence file attachment with security headers."""
    service = FindingService(db)
    file_path, content_type, filename = service.get_evidence_download(evidence_id=evidence_id, user=current_user)

    return FileResponse(
        path=str(file_path),
        media_type=content_type,
        filename=filename,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


