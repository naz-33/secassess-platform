from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.deps import get_current_user
from app.modules.auth import User

router = APIRouter(prefix="/recon", tags=["recon"])


@router.get("")
@router.get("/", include_in_schema=False)
def list_assets_placeholder(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Placeholder endpoint for listing discovered reconnaissance assets."""
    return {
        "status": "stub",
        "message": "Recon assets placeholder endpoint",
        "items": [],
    }
