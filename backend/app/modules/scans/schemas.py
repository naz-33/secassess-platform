import uuid
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, ConfigDict, Field
from app.modules.scans.models import ScanTool, ScanStatus


class ScanBase(BaseModel):
    assessment_id: uuid.UUID
    tool: ScanTool
    command: Optional[str] = None


class ScanCreate(BaseModel):
    tool: ScanTool
    target: Optional[str] = None
    options: Optional[Dict[str, Any]] = Field(default_factory=dict)


class ScanRead(ScanBase):
    id: uuid.UUID
    status: ScanStatus
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    raw_output: Optional[str] = None
    error: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
