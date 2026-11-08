from typing import List
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.modules.audit.models import AuditLog


class AuditRepository:
    """Repository handling database operations for audit_log."""

    def __init__(self, db: Session):
        self.db = db

    def create(self, log_entry: AuditLog) -> AuditLog:
        self.db.add(log_entry)
        self.db.commit()
        self.db.refresh(log_entry)
        return log_entry

    def list_entries(self, limit: int = 100, offset: int = 0) -> List[AuditLog]:
        return list(
            self.db.execute(
                select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)
            ).scalars().all()
        )
