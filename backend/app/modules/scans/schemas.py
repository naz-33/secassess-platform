import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict
from app.modules.scans.models import ScanTool, ScanStatus


class ScanBase(BaseModel):
    assessment_id: uuid.UUID
    tool: ScanTool
    command: Optional[str] = None


class ScanCreate(ScanBase):
    pass


class ScanRead(ScanBase):
    id: uuid.UUID
    status: ScanStatus
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    raw_output: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
