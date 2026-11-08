from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from app.core.security import decode_access_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


def get_current_user_payload(
    token: Optional[str] = Depends(oauth2_scheme),
) -> dict:
    """Dependency that extracts and decodes the current user's JWT payload."""
    if not token:
        # Placeholder user for initial unauthenticated stubs during testing
        return {
            "sub": "00000000-0000-0000-0000-000000000001",
            "email": "assessor@secassess.local",
            "role": "assessor",
        }
    try:
        payload = decode_access_token(token)
        return payload
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
