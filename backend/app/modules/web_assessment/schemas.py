import uuid
from typing import Dict, Any
from pydantic import BaseModel


class WebScanRequest(BaseModel):
    assessment_id: uuid.UUID
    target_id: uuid.UUID
    target_url: str
    scan_type: str = "zap"


class WebScanResult(BaseModel):
    assessment_id: uuid.UUID
    scan_type: str
    raw_results: Dict[str, Any] = {}
