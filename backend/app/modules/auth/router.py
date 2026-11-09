import uuid
from typing import List
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user, require_roles
from app.modules.auth.models import User
from app.modules.auth.schemas import (
    UserLogin,
    UserCreate,
    UserUpdate,
    UserRead,
    TokenResponse,
)
from app.modules.auth.service import AuthService

router = APIRouter(tags=["auth"])


@router.post("/auth/login", response_model=TokenResponse, status_code=status.HTTP_200_OK)
def login(
    login_in: UserLogin,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Authenticate with email and password and receive a Bearer access token."""
    service = AuthService(db)
    return service.authenticate_user(email=login_in.email, password=login_in.password)


@router.get("/auth/me", response_model=UserRead, status_code=status.HTTP_200_OK)
def get_current_user_profile(
    current_user: User = Depends(get_current_user),
) -> UserRead:
    """Retrieve profile of the currently authenticated user."""
    return UserRead.model_validate(current_user)


@router.post("/users", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(
    user_in: UserCreate,
    current_user: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
) -> UserRead:
    """Create a new user account (Admin only)."""
    service = AuthService(db)
    return service.register_user(user_in=user_in, creator=current_user)


@router.get("/users", response_model=List[UserRead], status_code=status.HTTP_200_OK)
def list_users(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
) -> List[UserRead]:
    """List all registered users (Admin only)."""
    service = AuthService(db)
    return service.list_users(limit=limit, offset=offset)


@router.patch("/users/{user_id}", response_model=UserRead, status_code=status.HTTP_200_OK)
def update_user(
    user_id: uuid.UUID,
    user_update: UserUpdate,
    current_user: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
) -> UserRead:
    """Update user role, name, or active status (Admin only)."""
    service = AuthService(db)
    return service.update_user(user_id=user_id, user_update=user_update, admin_user=current_user)
