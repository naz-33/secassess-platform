import uuid
from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, ConfigDict, Field
from app.modules.recon.models import AssetType


class AssetBase(BaseModel):
    assessment_id: uuid.UUID
    scan_id: Optional[uuid.UUID] = None
    type: AssetType
    value: str
    details: Optional[dict[str, Any]] = None


class AssetCreate(AssetBase):
    pass


class AssetRead(AssetBase):
    id: uuid.UUID
    created_at: datetime
    scan_ids: list[uuid.UUID] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)
