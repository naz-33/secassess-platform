from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db

router = APIRouter(prefix="/verification", tags=["verification"])


@router.get("/")
def list_verifications_placeholder(db: Session = Depends(get_db)):
    """Placeholder endpoint for assessor verifications."""
    # TODO: Connect to VerificationService
    return {
        "status": "stub",
        "message": "Verification placeholder endpoint",
        "items": [],
    }
