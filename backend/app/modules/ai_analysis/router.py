from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db

router = APIRouter(prefix="/ai-analysis", tags=["ai_analysis"])


@router.get("/")
def get_ai_status_placeholder(db: Session = Depends(get_db)):
    """Placeholder endpoint for AI analysis status."""
    # TODO: Connect to AIAnalysisService
    return {
        "status": "stub",
        "message": "AI analysis placeholder endpoint",
    }
