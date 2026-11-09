import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import require_roles
from app.modules.auth import User
from app.modules.audit.schemas import AuditLogRead
from app.modules.audit.service import AuditService

router = APIRouter(tags=["audit"])


@router.get("/audit-log", response_model=List[AuditLogRead], status_code=status.HTTP_200_OK)
@router.get("/audit", response_model=List[AuditLogRead], status_code=status.HTTP_200_OK)
def list_audit_logs(
    action: Optional[str] = Query(None, description="Filter by audit action type"),
    user_id: Optional[uuid.UUID] = Query(None, description="Filter by user UUID"),
    start_date: Optional[datetime] = Query(None, description="Filter by starting timestamp"),
    end_date: Optional[datetime] = Query(None, description="Filter by ending timestamp"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
) -> List[AuditLogRead]:
    """Retrieve audit log records with filtering and pagination (Admin only)."""
    service = AuditService(db)
    return service.list_logs(
        action=action,
        user_id=user_id,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
        offset=offset,
    )
