import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict
from app.modules.verification.models import VerificationDecision


class VerificationCreate(BaseModel):
    decision: VerificationDecision
    notes: Optional[str] = None
    evidence_reviewed: bool = False


class VerificationRead(BaseModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    assessor_id: uuid.UUID
    decision: VerificationDecision
    notes: Optional[str] = None
    evidence_reviewed: bool
    verified_at: datetime

    model_config = ConfigDict(from_attributes=True)
