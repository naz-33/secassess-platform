from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db

router = APIRouter(prefix="/web-assessment", tags=["web_assessment"])


@router.get("/")
def get_web_assessment_placeholder(db: Session = Depends(get_db)):
    """Placeholder endpoint for web assessment status."""
    # TODO: Connect to WebAssessmentService
    return {
        "status": "stub",
        "message": "Web assessment placeholder endpoint",
    }
