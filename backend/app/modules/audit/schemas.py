import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class AuditLogBase(BaseModel):
    action: str
    detail: Optional[str] = None


class AuditLogCreate(AuditLogBase):
    user_id: Optional[uuid.UUID] = None


class AuditLogRead(AuditLogBase):
    id: uuid.UUID
    user_id: Optional[uuid.UUID] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
