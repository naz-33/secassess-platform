from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db

router = APIRouter(prefix="/assessments", tags=["assessments"])


@router.get("/")
def list_assessments_placeholder(db: Session = Depends(get_db)):
    """Placeholder endpoint for listing assessments."""
    # TODO: Connect to AssessmentService.list_assessments
    return {
        "status": "stub",
        "message": "Assessments placeholder endpoint",
        "items": [],
    }
