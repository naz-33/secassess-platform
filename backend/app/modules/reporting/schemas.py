import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict


class ReportBase(BaseModel):
    assessment_id: uuid.UUID
    format: str = "pdf"


class ReportCreate(ReportBase):
    pass


class ReportRead(BaseModel):
    id: uuid.UUID
    assessment_id: uuid.UUID
    file_path: str
    generated_at: datetime

    model_config = ConfigDict(from_attributes=True)
