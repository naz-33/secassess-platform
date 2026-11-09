import uuid
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, ConfigDict
from app.modules.reporting.models import ReportFormat, ReportStatus


class ReportGenerateRequest(BaseModel):
    format: str = "docx"  # "docx" or "pdf"
    include_unverified_appendix: bool = True
    title: Optional[str] = None
    notes: Optional[str] = None


class ReportRead(BaseModel):
    id: uuid.UUID
    assessment_id: uuid.UUID
    version: int
    format: str
    status: str
    file_path: Optional[str] = None
    filename: Optional[str] = None
    sha256: Optional[str] = None
    size_bytes: Optional[int] = None
    generated_by: Optional[uuid.UUID] = None
    generated_at: Optional[datetime] = None
    template_version: str
    generator_version: str
    snapshot_json: Dict[str, Any] = {}
    unverified_count_at_generation: int
    confirmed_count_at_generation: int
    error: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Backwards compatibility
class ReportCreate(BaseModel):
    format: str = "docx"
    include_unverified_appendix: bool = True
    title: Optional[str] = None
    notes: Optional[str] = None
