from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db

router = APIRouter(prefix="/targets", tags=["targets"])


@router.get("/")
def list_targets_placeholder(db: Session = Depends(get_db)):
    """Placeholder endpoint for listing assessment targets."""
    # TODO: Connect to TargetService.list_targets
    return {
        "status": "stub",
        "message": "Targets placeholder endpoint",
        "items": [],
    }
