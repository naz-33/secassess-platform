import uuid
from datetime import datetime
from typing import Optional, List, Dict
from pydantic import BaseModel, Field, ConfigDict, field_validator
from app.modules.findings.models import (
    FindingSeverity,
    FindingStatus,
    FindingSource,
    EvidenceType,
)


def compute_risk_rating(severity: FindingSeverity) -> str:
    """Deterministic documented mapping from effective severity to risk rating."""
    mapping = {
        FindingSeverity.CRITICAL: "Critical Risk (Tier 1)",
        FindingSeverity.HIGH: "High Risk (Tier 2)",
        FindingSeverity.MEDIUM: "Medium Risk (Tier 3)",
        FindingSeverity.LOW: "Low Risk (Tier 4)",
        FindingSeverity.INFO: "Informational (Tier 5)",
    }
    return mapping.get(severity, "Informational (Tier 5)")


class EvidenceBase(BaseModel):
    type: EvidenceType
    content: Optional[str] = None
    file_path: Optional[str] = None
    label: Optional[str] = None
    scan_id: Optional[uuid.UUID] = None
    uploaded_by: Optional[uuid.UUID] = None
    sha256: Optional[str] = None
    original_filename: Optional[str] = None


class EvidenceCreate(EvidenceBase):
    pass


class NoteEvidenceCreate(BaseModel):
    notes: str = Field(..., min_length=1, description="Assessor manual notes or observation.")
    label: Optional[str] = Field("Assessor Note", description="Label for evidence item.")


class EvidenceRead(EvidenceBase):
    id: uuid.UUID
    finding_id: uuid.UUID
    captured_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SeverityUpdateRequest(BaseModel):
    severity: FindingSeverity
    justification: str = Field(..., min_length=10, description="Justification required for severity change.")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="CVSS base score between 0.0 and 10.0.")
    cvss_vector: Optional[str] = Field(None, max_length=100, description="Optional CVSS v3.1 vector string.")

    @field_validator("cvss_vector")
    @classmethod
    def validate_cvss_vector(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v.strip():
            clean = v.strip()
            # Loosely validate CVSS prefix
            if not (clean.startswith("CVSS:3.") or clean.startswith("CVSS:4.")):
                raise ValueError("CVSS vector must begin with CVSS:3.0, CVSS:3.1, or CVSS:4.0 prefix")
            return clean
        return v


class SeverityChangeRead(BaseModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    old_severity: FindingSeverity
    new_severity: FindingSeverity
    old_cvss: Optional[float] = None
    new_cvss: Optional[float] = None
    justification: str
    changed_by: uuid.UUID
    changed_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingBase(BaseModel):
    assessment_id: uuid.UUID
    scan_id: Optional[uuid.UUID] = None
    title: str
    category: str
    description: str
    severity: FindingSeverity
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    wstg_id: Optional[str] = None
    owasp_top10: Optional[str] = None
    cwe: Optional[str] = None
    affected_url: Optional[str] = None
    status: FindingStatus = FindingStatus.UNVERIFIED
    source: FindingSource = FindingSource.TOOL
    ai_analysis_id: Optional[uuid.UUID] = None
    remediation: Optional[str] = None
    fingerprint: Optional[str] = None


class FindingCreate(FindingBase):
    pass


class FindingRead(FindingBase):
    id: uuid.UUID
    original_severity: FindingSeverity
    final_severity: Optional[FindingSeverity] = None
    effective_severity: FindingSeverity
    severity_justification: Optional[str] = None
    verified_by: Optional[uuid.UUID] = None
    verified_at: Optional[datetime] = None
    risk_rating: Optional[str] = None
    assessment_name: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None
    evidences: List[EvidenceRead] = []

    model_config = ConfigDict(from_attributes=True)

    @field_validator("risk_rating", mode="before")
    @classmethod
    def populate_risk_rating(cls, v: Optional[str], info) -> Optional[str]:
        if v is not None:
            return v
        # Compute if not explicitly set
        data = info.data
        eff = data.get("final_severity") or data.get("original_severity") or data.get("severity")
        if eff:
            return compute_risk_rating(eff)
        return "Informational (Tier 5)"


class FindingsSummary(BaseModel):
    total: int
    by_severity: Dict[str, int]
    by_category: Dict[str, int]
    confirmed_by_category: Dict[str, int] = {}
    by_status: Dict[str, int]
    confirmed_by_effective_severity: Dict[str, int]
    unverified_count: int
    verified_count: int
    verification_progress: float
