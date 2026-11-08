from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("/")
def list_findings_placeholder(db: Session = Depends(get_db)):
    """Placeholder endpoint for listing findings."""
    # TODO: Connect to FindingService.list_findings
    return {
        "status": "stub",
        "message": "Findings placeholder endpoint",
        "items": [],
    }
