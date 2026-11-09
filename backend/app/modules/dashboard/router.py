import uuid
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.deps import get_current_user
from app.modules.auth import User
from app.modules.dashboard.service import DashboardService
from app.modules.dashboard.schemas import (
    AssessmentDashboardResponse,
    GlobalDashboardResponse,
    DashboardMetrics,
)

router = APIRouter(tags=["dashboard"])


@router.get("/assessments/{assessment_id}/dashboard", response_model=AssessmentDashboardResponse, status_code=status.HTTP_200_OK)
def get_assessment_dashboard(
    assessment_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AssessmentDashboardResponse:
    """Fetch consolidated dashboard data for a single assessment."""
    service = DashboardService(db)
    return service.get_assessment_dashboard(assessment_id=assessment_id, user=current_user)


@router.get("/dashboard", response_model=GlobalDashboardResponse, status_code=status.HTTP_200_OK)
def get_global_dashboard(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> GlobalDashboardResponse:
    """Fetch global overview counts across all assessments."""
    service = DashboardService(db)
    return service.get_global_dashboard(limit=limit, offset=offset, user=current_user)


@router.get("/dashboard/metrics", response_model=DashboardMetrics, status_code=status.HTTP_200_OK)
def get_dashboard_metrics(db: Session = Depends(get_db)):
    """Fetch dashboard aggregation metrics and chart data (backwards compatibility)."""
    service = DashboardService(db)
    return service.get_metrics()
