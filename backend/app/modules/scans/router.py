from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("/")
def list_scans_placeholder(db: Session = Depends(get_db)):
    """Placeholder endpoint for listing scans."""
    # TODO: Connect to ScanService.list_scans_for_assessment
    return {
        "status": "stub",
        "message": "Scans placeholder endpoint",
        "items": [],
    }
