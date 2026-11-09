import uuid
from datetime import datetime
from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.modules.audit.models import AuditLog


class AuditRepository:
    """Repository handling database operations for audit_log (strictly append-only)."""

    def __init__(self, db: Session):
        self.db = db

    def create(self, log_entry: AuditLog) -> AuditLog:
        """Append-only creation of an audit log entry."""
        self.db.add(log_entry)
        self.db.commit()
        self.db.refresh(log_entry)
        return log_entry

    def list_entries(
        self,
        action: Optional[str] = None,
        user_id: Optional[uuid.UUID] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditLog]:
        query = select(AuditLog)
        if action:
            query = query.where(AuditLog.action == action)
        if user_id:
            query = query.where(AuditLog.user_id == user_id)
        if start_date:
            query = query.where(AuditLog.created_at >= start_date)
        if end_date:
            query = query.where(AuditLog.created_at <= end_date)

        query = query.order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)
        return list(self.db.execute(query).scalars().all())

    def list_assessment_activity(
        self,
        assessment_id: uuid.UUID,
        limit: int = 10,
        allowed_actions: Optional[List[str]] = None,
    ) -> List[AuditLog]:
        query = select(AuditLog).where(AuditLog.detail.like(f"%{assessment_id}%"))
        if allowed_actions:
            query = query.where(AuditLog.action.in_(allowed_actions))
        query = query.order_by(AuditLog.created_at.desc()).limit(limit)
        return list(self.db.execute(query).scalars().all())

