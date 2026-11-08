import uuid
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict


class ScopeItemBase(BaseModel):
    asset: str
    in_scope: bool = True
    notes: Optional[str] = None


class ScopeItemCreate(ScopeItemBase):
    pass


class ScopeItemRead(ScopeItemBase):
    id: uuid.UUID
    target_id: uuid.UUID
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TargetBase(BaseModel):
    name: str
    base_url: str
    description: Optional[str] = None
    authorization_note: Optional[str] = None


class TargetCreate(TargetBase):
    scope_items: Optional[List[ScopeItemCreate]] = None


class TargetRead(TargetBase):
    id: uuid.UUID
    created_at: datetime
    scope_items: List[ScopeItemRead] = []

    model_config = ConfigDict(from_attributes=True)
