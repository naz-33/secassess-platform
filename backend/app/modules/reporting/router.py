import uuid
from typing import List
from fastapi import APIRouter, Depends, BackgroundTasks, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user, require_roles
from app.core.exceptions import NotFoundException
from app.modules.auth import User
from app.modules.reporting.schemas import ReportGenerateRequest, ReportRead
from app.modules.reporting.service import ReportingService

router = APIRouter(tags=["reporting"])


@router.post(
    "/assessments/{assessment_id}/reports",
    response_model=ReportRead,
    status_code=status.HTTP_202_ACCEPTED,
)
def generate_assessment_report(
    assessment_id: uuid.UUID,
    report_in: ReportGenerateRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_roles("assessor", "admin")),
    db: Session = Depends(get_db),
) -> ReportRead:
    """Request compilation of an immutable assessment report (DOCX / PDF)."""
    service = ReportingService(db)
    return service.request_report_generation(
        assessment_id=assessment_id,
        request=report_in,
        user=current_user,
        background_tasks=background_tasks,
    )


@router.get(
    "/assessments/{assessment_id}/reports",
    response_model=List[ReportRead],
    status_code=status.HTTP_200_OK,
)
def list_assessment_reports(
    assessment_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[ReportRead]:
    """List all reports generated for an assessment."""
    service = ReportingService(db)
    return service.list_reports(assessment_id)


@router.get(
    "/reports/{report_id}",
    response_model=ReportRead,
    status_code=status.HTTP_200_OK,
)
def get_report_metadata(
    report_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ReportRead:
    """Retrieve metadata and generation status for a specific report."""
    service = ReportingService(db)
    report = service.get_report(report_id)
    if not report:
        raise NotFoundException(resource="Report", identifier=report_id)
    return report


@router.get(
    "/reports/{report_id}/download",
    status_code=status.HTTP_200_OK,
)
def download_report_file(
    report_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> FileResponse:
    """Download the generated report document with SHA-256 integrity verification."""
    service = ReportingService(db)
    file_path, media_type, filename = service.get_report_download(report_id, user=current_user)

    return FileResponse(
        path=str(file_path),
        media_type=media_type,
        filename=filename,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.delete(
    "/reports/{report_id}",
    status_code=status.HTTP_200_OK,
)
def delete_report(
    report_id: uuid.UUID,
    current_user: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
):
    """Admin-only deletion of an assessment report artifact."""
    service = ReportingService(db)
    service.delete_report(report_id, user=current_user)
    return {"status": "deleted", "report_id": str(report_id)}
