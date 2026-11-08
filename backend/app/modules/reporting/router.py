from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db

router = APIRouter(prefix="/reports", tags=["reporting"])


@router.get("/")
def list_reports_placeholder(db: Session = Depends(get_db)):
    """Placeholder endpoint for listing generated reports."""
    # TODO: Connect to ReportingService.list_reports
    return {
        "status": "stub",
        "message": "Reports placeholder endpoint",
        "items": [],
    }
