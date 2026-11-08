import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict
from app.modules.assessments.models import AssessmentStatus


class AssessmentBase(BaseModel):
    name: str
    target_id: uuid.UUID
    status: AssessmentStatus = AssessmentStatus.DRAFT


class AssessmentCreate(AssessmentBase):
    pass


class AssessmentRead(AssessmentBase):
    id: uuid.UUID
    created_by: uuid.UUID
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
