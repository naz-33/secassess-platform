import json
import uuid
from datetime import datetime
from typing import List, Optional, Any
from sqlalchemy.orm import Session
from app.modules.audit.models import AuditLog
from app.modules.audit.repository import AuditRepository
from app.modules.audit.schemas import AuditLogRead


class AuditService:
    """Public business logic service for system audit logging (strictly append-only)."""

    def __init__(self, db: Session):
        self.db = db
        self.repository = AuditRepository(db)

    def log_action(
        self,
        action: str,
        detail: Optional[Any] = None,
        user_id: Optional[uuid.UUID] = None,
    ) -> AuditLogRead:
        """
        Record an immutable audit trail event.
        Guaranteed to sanitize and exclude plaintext secrets or binary file contents.
        """
        detail_str = detail
        if isinstance(detail, (dict, list)):
            try:
                # Sanitize any accidental sensitive keys if present
                clean_detail = self._sanitize_detail(detail)
                detail_str = json.dumps(clean_detail)
            except Exception:
                detail_str = str(detail)
        elif detail is not None and not isinstance(detail, str):
            detail_str = str(detail)

        log_entry = AuditLog(
            user_id=user_id,
            action=action,
            detail=detail_str,
        )
        created = self.repository.create(log_entry)
        return AuditLogRead.model_validate(created)

    def list_logs(
        self,
        action: Optional[str] = None,
        user_id: Optional[uuid.UUID] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditLogRead]:
        """Fetch audit log records ordered by most recent first."""
        records = self.repository.list_entries(
            action=action,
            user_id=user_id,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            offset=offset,
        )
        return [AuditLogRead.model_validate(r) for r in records]

    def list_assessment_activity(
        self,
        assessment_id: uuid.UUID,
        limit: int = 10,
        is_admin: bool = False,
    ) -> List[AuditLogRead]:
        """Fetch recent activity for an assessment, filtering non-sensitive actions for non-admins."""
        allowed_actions = None
        if not is_admin:
            allowed_actions = [
                "assessment_created",
                "scan_triggered",
                "scan_started",
                "scan_completed",
                "scan_failed",
                "verification_recorded",
                "ai_analysis_started",
                "ai_analysis_completed",
                "ai_analysis_reviewed",
                "report_generation_requested",
                "report_generated",
                "report_downloaded",
                "findings_exported",
            ]
        records = self.repository.list_assessment_activity(
            assessment_id=assessment_id,
            limit=limit,
            allowed_actions=allowed_actions,
        )
        return [AuditLogRead.model_validate(r) for r in records]


    def _sanitize_detail(self, data: Any) -> Any:
        sensitive_keys = {"password", "token", "access_token", "secret", "file_bytes"}
        if isinstance(data, dict):
            return {
                k: "[REDACTED]" if k.lower() in sensitive_keys else self._sanitize_detail(v)
                for k, v in data.items()
            }
        elif isinstance(data, list):
            return [self._sanitize_detail(item) for item in data]
        return data
