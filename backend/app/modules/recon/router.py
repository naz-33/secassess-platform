from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db

router = APIRouter(prefix="/recon", tags=["recon"])


@router.get("/")
def list_assets_placeholder(db: Session = Depends(get_db)):
    """Placeholder endpoint for listing discovered reconnaissance assets."""
    # TODO: Connect to ReconService.list_assets
    return {
        "status": "stub",
        "message": "Recon assets placeholder endpoint",
        "items": [],
    }
