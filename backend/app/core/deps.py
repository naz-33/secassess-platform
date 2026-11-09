import uuid
from datetime import datetime, timezone
from typing import Optional, Callable
from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.exceptions import UnauthorizedException, ForbiddenException
from app.core.security import decode_access_token
from app.modules.auth.models import User

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_PREFIX}/auth/login",
    auto_error=False,
)


def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Dependency that extracts, decodes, and validates the current user's JWT access token."""
    if not token:
        raise UnauthorizedException("Authentication required. Please provide a Bearer token.")

    try:
        payload = decode_access_token(token)
    except Exception:
        raise UnauthorizedException("Could not validate credentials or token expired.")

    user_id_str = payload.get("sub")
    if not user_id_str:
        raise UnauthorizedException("Token payload missing subject.")

    try:
        user_id = uuid.UUID(str(user_id_str))
    except ValueError:
        raise UnauthorizedException("Invalid token subject identifier.")

    user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if not user:
        raise UnauthorizedException("User associated with token no longer exists.")

    if not user.is_active:
        raise ForbiddenException("User account is inactive. Please contact administrator.")

    if user.locked_until:
        locked_until = user.locked_until
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if locked_until > datetime.now(timezone.utc):
            raise UnauthorizedException("User account is temporarily locked.")

    return user


def require_roles(*roles: str) -> Callable[[User], User]:
    """Dependency factory checking that the authenticated user possesses one of the required roles."""
    def role_verifier(current_user: User = Depends(get_current_user)) -> User:
        user_role_val = current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role)
        target_roles = [r.lower() for r in roles]
        if user_role_val.lower() not in target_roles:
            raise ForbiddenException(
                f"Operation forbidden. Required roles: {', '.join(roles)}. Current role: {user_role_val}."
            )
        return current_user

    return role_verifier
