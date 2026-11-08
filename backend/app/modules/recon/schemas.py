import uuid
from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, ConfigDict
from app.modules.recon.models import AssetType


class AssetBase(BaseModel):
    assessment_id: uuid.UUID
    type: AssetType
    value: str
    details: Optional[dict[str, Any]] = None


class AssetCreate(AssetBase):
    pass


class AssetRead(AssetBase):
    id: uuid.UUID
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
