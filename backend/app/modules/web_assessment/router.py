from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.deps import get_current_user
from app.modules.auth import User

router = APIRouter(prefix="/web-assessment", tags=["web_assessment"])


@router.get("")
@router.get("/", include_in_schema=False)
def get_web_assessment_placeholder(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Placeholder endpoint for web assessment status."""
    return {
        "status": "stub",
        "message": "Web assessment placeholder endpoint",
    }
