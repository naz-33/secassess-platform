from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.modules.dashboard.service import DashboardService
from app.modules.dashboard.schemas import DashboardMetrics

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/metrics", response_model=DashboardMetrics)
def get_dashboard_metrics(db: Session = Depends(get_db)):
    """Fetch dashboard aggregation metrics and chart data."""
    service = DashboardService(db)
    return service.get_metrics()
