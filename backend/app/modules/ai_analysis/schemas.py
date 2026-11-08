import uuid
from datetime import datetime
from typing import Optional, Any, Dict
from pydantic import BaseModel, ConfigDict
from app.modules.ai_analysis.models import AIFunction


class AIAnalysisBase(BaseModel):
    finding_id: Optional[uuid.UUID] = None
    scan_id: Optional[uuid.UUID] = None
    function: AIFunction
    model: str
    prompt_summary: Optional[str] = None
    response_json: Optional[Dict[str, Any]] = None


class AIAnalysisCreate(AIAnalysisBase):
    pass


class AIAnalysisRead(AIAnalysisBase):
    id: uuid.UUID
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
