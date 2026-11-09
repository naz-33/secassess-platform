import re
import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict, field_validator
from app.modules.auth.models import UserRole

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def clean_and_validate_email(v: str) -> str:
    if not isinstance(v, str):
        raise ValueError("Email must be a string.")
    clean = v.strip().lower()
    if not EMAIL_REGEX.match(clean):
        raise ValueError("Invalid email format.")
    return clean


class UserBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    email: str = Field(..., max_length=255)
    role: UserRole = UserRole.ASSESSOR

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return clean_and_validate_email(v)


class UserCreate(UserBase):
    password: str = Field(..., min_length=12, description="Password must be at least 12 characters.")


class UserUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None


class UserRead(BaseModel):
    id: uuid.UUID
    name: str
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserLogin(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return clean_and_validate_email(v)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserRead
