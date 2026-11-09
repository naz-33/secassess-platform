import uuid
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict, Field


class ScopeItemBase(BaseModel):
    asset: str = Field(..., min_length=1, max_length=1024, description="URL, domain, IP, or CIDR block")
    in_scope: bool = Field(default=True, description="True if allowed, False if explicitly out-of-scope")
    notes: Optional[str] = Field(default=None, description="Optional notes regarding this scope boundary")


class ScopeItemCreate(ScopeItemBase):
    pass


class ScopeItemUpdate(BaseModel):
    asset: Optional[str] = Field(default=None, min_length=1, max_length=1024)
    in_scope: Optional[bool] = None
    notes: Optional[str] = None


class ScopeItemRead(ScopeItemBase):
    id: uuid.UUID
    target_id: uuid.UUID
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TargetBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Target identifier name")
    base_url: str = Field(..., min_length=1, max_length=1024, description="Primary base URL or hostname")
    description: Optional[str] = Field(default=None, description="Target environment description")
    authorization_note: Optional[str] = Field(
        default=None,
        description="Formal authorization documentation note or agreement reference",
    )


class TargetCreate(TargetBase):
    scope_items: Optional[List[ScopeItemCreate]] = None


class TargetUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    base_url: Optional[str] = Field(default=None, min_length=1, max_length=1024)
    description: Optional[str] = None
    authorization_note: Optional[str] = None


class TargetRead(TargetBase):
    id: uuid.UUID
    created_at: datetime
    scope_items: List[ScopeItemRead] = []

    model_config = ConfigDict(from_attributes=True)


class ScopeValidationRequest(BaseModel):
    asset: str = Field(..., min_length=1, description="Candidate asset URL, host, IP, or path to validate")


class ScopeValidationResponse(BaseModel):
    asset: str
    target_id: uuid.UUID
    in_scope: bool
    reason: str
