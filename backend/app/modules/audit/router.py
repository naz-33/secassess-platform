from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/")
def list_audit_logs_placeholder(db: Session = Depends(get_db)):
    """Placeholder endpoint for viewing audit logs."""
    # TODO: Connect to AuditService.list_logs
    return {
        "status": "stub",
        "message": "Audit logs placeholder endpoint",
        "items": [],
    }
