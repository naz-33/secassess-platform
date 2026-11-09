"""Pydantic schemas and structured output schemas for AI analysis."""
import enum
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
from app.modules.ai_analysis.models import AIFunction, AIAnalysisStatus, AIReviewStatus
from app.modules.findings import FindingSeverity


class ConfidenceLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# =====================================================================
# Structured Output Schemas (Target Schemas for Gemini Structured JSON)
# =====================================================================

class KeyObservation(BaseModel):
    observation: str = Field(..., description="Technical observation from scan output.")
    why_it_matters: str = Field(..., description="Operational or security impact explanation.")
    evidence_ids: List[str] = Field(default_factory=list, description="Cited evidence IDs (UUIDs).")


class CandidateFinding(BaseModel):
    title: str = Field(..., description="Descriptive title of proposed vulnerability.")
    category: str = Field(..., description="Vulnerability category.")
    evidence_excerpt: str = Field(..., description="Short exact excerpt from the supplied scan output.")
    explanation: str = Field(..., description="Evidence-grounded explanation of the potential issue.")
    recommended_fix: str = Field(..., description="Recommended remediation guidance.")
    description: str = Field("", description="Compatibility field for existing candidate consumers.")
    suggested_severity: FindingSeverity = Field(..., description="Advisory severity rating.")
    confidence: ConfidenceLevel = Field(..., description="Confidence level in this candidate finding.")
    evidence_ids: List[str] = Field(default_factory=list, description="Supporting evidence IDs.")
    wstg_id: Optional[str] = Field(None, description="Optional OWASP WSTG test ID.")
    remediation: Optional[str] = Field(None, description="Recommended remediation guidance.")
    affected_url: Optional[str] = Field(None, description="Optional affected endpoint or asset.")


class ScanInterpretationResponse(BaseModel):
    summary: str = Field(..., description="Plain-language summary of scan results.")
    key_observations: List[KeyObservation] = Field(default_factory=list)
    suggested_candidate_findings: List[CandidateFinding] = Field(default_factory=list)
    caveats: List[str] = Field(default_factory=list, description="Limitations and false positive caveats.")
    confidence: ConfidenceLevel = Field(..., description="Overall confidence rating.")
    ai_generated: bool = Field(default=True, description="Explicit flag indicating AI origin.")
    disclaimer: str = Field(
        default="AI-generated. Must be verified by an assessor against the evidence.",
        description="Mandatory assessor verification disclaimer.",
    )


class PrioritizedFinding(BaseModel):
    finding_id: str = Field(..., description="UUID of the existing assessment finding.")
    rank: int = Field(..., description="Numerical rank ordering from 1 (highest priority).")
    rationale: str = Field(..., description="Justification for prioritization ranking.")
    likely_impact: str = Field(..., description="Realistic adversary impact description.")
    exploitability_notes: str = Field(..., description="Exploit prerequisites and conditions.")
    suggested_severity: FindingSeverity = Field(..., description="Advisory severity assessment.")
    remediation_steps: List[str] = Field(default_factory=list, description="Concrete technical remediation steps.")
    references: List[str] = Field(default_factory=list, description="Authoritative standard IDs (WSTG/CWE/OWASP).")
    confidence: ConfidenceLevel = Field(..., description="Confidence rating for this item.")
    caveats: List[str] = Field(default_factory=list)


class PrioritizationResponse(BaseModel):
    overall_risk_narrative: str = Field(..., description="High-level narrative of risk exposure.")
    prioritized_findings: List[PrioritizedFinding] = Field(default_factory=list)
    confidence: ConfidenceLevel = Field(..., description="Overall confidence rating.")
    caveats: List[str] = Field(default_factory=list)
    ai_generated: bool = Field(default=True)
    disclaimer: str = Field(default="AI-generated. Must be verified by an assessor against the evidence.")


class FindingExplanationResponse(BaseModel):
    explanation: str = Field(..., description="Detailed technical breakdown of vulnerability.")
    likely_impact: str = Field(..., description="Real-world operational impact.")
    exploitability_notes: str = Field(..., description="Exploitation context and prerequisites.")
    suggested_severity: FindingSeverity = Field(..., description="Advisory severity rating.")
    remediation_steps: List[str] = Field(default_factory=list, description="Specific remediation instructions.")
    references: List[str] = Field(default_factory=list, description="Standard references (WSTG, CWE, OWASP).")
    confidence: ConfidenceLevel = Field(..., description="Confidence level.")
    caveats: List[str] = Field(default_factory=list)
    ai_generated: bool = Field(default=True)
    disclaimer: str = Field(default="AI-generated. Must be verified by an assessor against the evidence.")


class ExecutiveSummaryResponse(BaseModel):
    executive_summary: str = Field(..., description="Concise, non-technical overview of posture.")
    scope_and_method: str = Field(..., description="Description of testing scope and methods.")
    key_risks: List[str] = Field(default_factory=list, description="Key confirmed risks.")
    recommended_next_steps: List[str] = Field(default_factory=list, description="Actionable next steps.")
    caveats: List[str] = Field(default_factory=list, description="Assessment boundaries and constraints.")
    confidence: ConfidenceLevel = Field(..., description="Confidence rating.")
    ai_generated: bool = Field(default=True)
    disclaimer: str = Field(default="AI-generated. Must be verified by an assessor against the evidence.")


# =====================================================================
# API Request / Response DTOs
# =====================================================================

class TriggerAnalysisRequest(BaseModel):
    force: bool = Field(default=False, description="Bypass cache and force a new LLM call.")


class PromoteSuggestionRequest(BaseModel):
    suggestion_index: int = Field(..., ge=0, description="0-indexed position in suggested_candidate_findings.")


class ReviewAnalysisRequest(BaseModel):
    review_status: AIReviewStatus = Field(..., description="Assessor decision: approved or rejected.")
    edited_text: Optional[str] = Field(None, description="Optional assessor edited narrative text.")
    notes: Optional[str] = Field(None, description="Assessor review rationale or notes.")


class AIAnalysisRead(BaseModel):
    id: uuid.UUID
    assessment_id: uuid.UUID
    finding_id: Optional[uuid.UUID] = None
    scan_id: Optional[uuid.UUID] = None
    function: AIFunction
    status: AIAnalysisStatus
    requested_by: Optional[uuid.UUID] = None
    model: str
    prompt_version: str
    prompt_summary: Optional[str] = None
    input_hash: str
    redaction_report: Dict[str, Any]
    response_json: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    latency_ms: Optional[int] = None
    review_status: AIReviewStatus
    reviewed_by: Optional[uuid.UUID] = None
    reviewed_at: Optional[datetime] = None
    edited_text: Optional[str] = None
    review_notes: Optional[str] = None
    created_at: datetime
    ai_generated: bool = True
    disclaimer: str = "AI-generated. Must be verified by an assessor against the evidence."

    model_config = ConfigDict(from_attributes=True)


class AIStatusRead(BaseModel):
    enabled: bool
    configured: bool
    model: str
    limits: Dict[str, int]
    remaining_budget: Dict[str, int]
