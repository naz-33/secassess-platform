"""FastAPI router for AI-assisted security analysis endpoints."""
import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, BackgroundTasks, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user, require_roles
from app.core.exceptions import NotFoundException
from app.modules.auth import User
from app.modules.findings import FindingRead
from app.modules.ai_analysis.models import (
    AIFunction,
    AIAnalysisStatus,
    AIReviewStatus,
)
from app.modules.ai_analysis.schemas import (
    AIAnalysisRead,
    AIStatusRead,
    PromoteSuggestionRequest,
    ReviewAnalysisRequest,
)
from app.modules.ai_analysis.service import AIAnalysisService

router = APIRouter(tags=["ai_analysis"])


@router.get("/ai/status", response_model=AIStatusRead, status_code=status.HTTP_200_OK)
@router.get("/ai-analysis/status", response_model=AIStatusRead, status_code=status.HTTP_200_OK)
@router.get("/ai-analysis", response_model=AIStatusRead, status_code=status.HTTP_200_OK)
def get_ai_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AIStatusRead:
    """Retrieve AI subsystem configuration, active model, and user quota remaining."""
    service = AIAnalysisService(db)
    return service.get_status(current_user)


@router.post(
    "/assessments/{assessment_id}/scans/{scan_id}/ai/interpret",
    response_model=AIAnalysisRead,
    status_code=status.HTTP_202_ACCEPTED,
)
def interpret_scan(
    assessment_id: uuid.UUID,
    scan_id: uuid.UUID,
    force: bool = Query(default=False, description="Bypass cache and force re-analysis"),
    background_tasks: BackgroundTasks = None,
    current_user: User = Depends(require_roles("assessor", "admin")),
    db: Session = Depends(get_db),
) -> AIAnalysisRead:
    """Trigger AI technical interpretation and candidate finding suggestions for a scan."""
    service = AIAnalysisService(db)
    return service.trigger_scan_interpretation(
        assessment_id=assessment_id,
        scan_id=scan_id,
        user=current_user,
        force=force,
        background_tasks=background_tasks,
    )


@router.post(
    "/assessments/{assessment_id}/ai/prioritize",
    response_model=AIAnalysisRead,
    status_code=status.HTTP_202_ACCEPTED,
)
def prioritize_assessment_findings(
    assessment_id: uuid.UUID,
    force: bool = Query(default=False, description="Bypass cache and force re-analysis"),
    background_tasks: BackgroundTasks = None,
    current_user: User = Depends(require_roles("assessor", "admin")),
    db: Session = Depends(get_db),
) -> AIAnalysisRead:
    """Trigger AI risk prioritization and remediation sequencing for assessment findings."""
    service = AIAnalysisService(db)
    return service.trigger_prioritization(
        assessment_id=assessment_id,
        user=current_user,
        force=force,
        background_tasks=background_tasks,
    )


@router.post(
    "/findings/{finding_id}/ai/explain",
    response_model=AIAnalysisRead,
    status_code=status.HTTP_202_ACCEPTED,
)
def explain_finding(
    finding_id: uuid.UUID,
    force: bool = Query(default=False, description="Bypass cache and force re-analysis"),
    background_tasks: BackgroundTasks = None,
    current_user: User = Depends(require_roles("assessor", "admin")),
    db: Session = Depends(get_db),
) -> AIAnalysisRead:
    """Trigger deep technical explanation and concrete remediation advice for one finding."""
    service = AIAnalysisService(db)
    return service.trigger_finding_explanation(
        finding_id=finding_id,
        user=current_user,
        force=force,
        background_tasks=background_tasks,
    )


@router.post(
    "/assessments/{assessment_id}/ai/summary",
    response_model=AIAnalysisRead,
    status_code=status.HTTP_202_ACCEPTED,
)
def summarize_assessment(
    assessment_id: uuid.UUID,
    force: bool = Query(default=False, description="Bypass cache and force re-analysis"),
    background_tasks: BackgroundTasks = None,
    current_user: User = Depends(require_roles("assessor", "admin")),
    db: Session = Depends(get_db),
) -> AIAnalysisRead:
    """Draft an executive summary grounded exclusively in confirmed assessment findings."""
    service = AIAnalysisService(db)
    return service.trigger_executive_summary(
        assessment_id=assessment_id,
        user=current_user,
        force=force,
        background_tasks=background_tasks,
    )


@router.get(
    "/ai-analyses/{analysis_id}",
    response_model=AIAnalysisRead,
    status_code=status.HTTP_200_OK,
)
def get_ai_analysis(
    analysis_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AIAnalysisRead:
    """Retrieve details, status, and structured output of an AI analysis."""
    service = AIAnalysisService(db)
    analysis = service.get_analysis(analysis_id)
    if not analysis:
        raise NotFoundException("AIAnalysis", analysis_id)
    return analysis


@router.get(
    "/assessments/{assessment_id}/ai-analyses",
    response_model=List[AIAnalysisRead],
    status_code=status.HTTP_200_OK,
)
def list_assessment_analyses(
    assessment_id: uuid.UUID,
    function: Optional[AIFunction] = Query(None, description="Filter by AI function"),
    status_filter: Optional[AIAnalysisStatus] = Query(None, alias="status", description="Filter by execution status"),
    review_status: Optional[AIReviewStatus] = Query(None, description="Filter by review status"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[AIAnalysisRead]:
    """List historical AI analyses associated with an assessment."""
    service = AIAnalysisService(db)
    return service.list_analyses_for_assessment(
        assessment_id=assessment_id,
        function=function,
        status=status_filter,
        review_status=review_status,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/ai-analyses/{analysis_id}/promote",
    response_model=FindingRead,
    status_code=status.HTTP_200_OK,
)
def promote_ai_suggestion(
    analysis_id: uuid.UUID,
    promote_in: PromoteSuggestionRequest,
    current_user: User = Depends(require_roles("assessor", "admin")),
    db: Session = Depends(get_db),
) -> FindingRead:
    """Promote an AI candidate finding into an official unverified finding."""
    service = AIAnalysisService(db)
    return service.promote_candidate_suggestion(
        analysis_id=analysis_id,
        promote_in=promote_in,
        user=current_user,
    )


@router.patch(
    "/ai-analyses/{analysis_id}/review",
    response_model=AIAnalysisRead,
    status_code=status.HTTP_200_OK,
)
def review_ai_analysis(
    analysis_id: uuid.UUID,
    review_in: ReviewAnalysisRequest,
    current_user: User = Depends(require_roles("assessor", "admin")),
    db: Session = Depends(get_db),
) -> AIAnalysisRead:
    """Review and approve or reject an executive summary or analysis draft."""
    service = AIAnalysisService(db)
    return service.review_analysis(
        analysis_id=analysis_id,
        review_in=review_in,
        user=current_user,
    )
