from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/me")
def get_current_user_placeholder(db: Session = Depends(get_db)):
    """Placeholder endpoint for retrieving authenticated user profile."""
    # TODO: Connect to AuthService.get_user_by_id with active session
    return {
        "status": "stub",
        "message": "Auth profile placeholder endpoint",
        "user": None,
    }
