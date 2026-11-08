import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict
from app.modules.verification.models import VerificationDecision


class VerificationBase(BaseModel):
    finding_id: uuid.UUID
    decision: VerificationDecision
    notes: Optional[str] = None


class VerificationCreate(VerificationBase):
    pass


class VerificationRead(VerificationBase):
    id: uuid.UUID
    assessor_id: uuid.UUID
    verified_at: datetime

    model_config = ConfigDict(from_attributes=True)
