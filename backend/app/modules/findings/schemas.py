import uuid
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict
from app.modules.findings.models import FindingSeverity, FindingStatus, FindingSource, EvidenceType


class EvidenceBase(BaseModel):
    type: EvidenceType
    content: Optional[str] = None
    file_path: Optional[str] = None


class EvidenceCreate(EvidenceBase):
    pass


class EvidenceRead(EvidenceBase):
    id: uuid.UUID
    finding_id: uuid.UUID
    captured_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingBase(BaseModel):
    assessment_id: uuid.UUID
    scan_id: Optional[uuid.UUID] = None
    title: str
    category: str
    description: str
    severity: FindingSeverity
    status: FindingStatus = FindingStatus.UNVERIFIED
    source: FindingSource = FindingSource.TOOL
    remediation: Optional[str] = None


class FindingCreate(FindingBase):
    pass


class FindingRead(FindingBase):
    id: uuid.UUID
    created_at: datetime
    evidences: List[EvidenceRead] = []

    model_config = ConfigDict(from_attributes=True)
