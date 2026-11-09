import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    UnauthorizedException,
    ForbiddenException,
    ConflictException,
    NotFoundException,
)
from app.core.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    validate_password_strength,
)
from app.modules.audit import AuditService
from app.modules.auth.models import User, UserRole
from app.modules.auth.repository import UserRepository
from app.modules.auth.schemas import (
    UserCreate,
    UserUpdate,
    UserRead,
    TokenResponse,
)


class AuthService:
    """Public business logic service for authentication and user management."""

    def __init__(self, db: Session):
        self.db = db
        self.repository = UserRepository(db)
        self.audit_service = AuditService(db)

    def authenticate_user(self, email: str, password: str) -> TokenResponse:
        """
        Authenticate user by email and password with brute-force lockout defense.
        Returns generic error messages to prevent user enumeration.
        """
        clean_email = email.strip().lower()
        user = self.repository.get_by_email(clean_email)

        now = datetime.now(timezone.utc)

        # Check if user exists and is currently locked
        if user and user.locked_until:
            # Ensure timezone-aware comparison
            locked_until = user.locked_until
            if locked_until.tzinfo is None:
                locked_until = locked_until.replace(tzinfo=timezone.utc)

            if locked_until > now:
                self.audit_service.log_action(
                    action="login_locked",
                    detail={"email": clean_email, "locked_until": locked_until.isoformat()},
                    user_id=user.id,
                )
                raise UnauthorizedException(
                    "Account is temporarily locked due to multiple failed login attempts. Please try again later."
                )
            else:
                # Lock expired, reset
                user.locked_until = None
                user.failed_login_count = 0
                self.repository.update(user)

        # Verify password
        if not user or not verify_password(password, user.password_hash):
            if user:
                user.failed_login_count += 1
                if user.failed_login_count >= settings.LOGIN_MAX_ATTEMPTS:
                    user.locked_until = now + timedelta(minutes=settings.LOCKOUT_MINUTES)
                    self.repository.update(user)
                    self.audit_service.log_action(
                        action="user_lockout",
                        detail={
                            "email": clean_email,
                            "failed_attempts": user.failed_login_count,
                            "locked_until": user.locked_until.isoformat(),
                        },
                        user_id=user.id,
                    )
                    raise UnauthorizedException(
                        "Account is temporarily locked due to multiple failed login attempts. Please try again later."
                    )
                else:
                    self.repository.update(user)
                    self.audit_service.log_action(
                        action="login_failed",
                        detail={"email": clean_email, "failed_attempts": user.failed_login_count},
                        user_id=user.id,
                    )
            else:
                self.audit_service.log_action(
                    action="login_failed",
                    detail={"email": clean_email, "reason": "invalid_credentials"},
                    user_id=None,
                )

            raise UnauthorizedException("Invalid email or password.")

        # Check active status
        if not user.is_active:
            self.audit_service.log_action(
                action="login_failed",
                detail={"email": clean_email, "reason": "account_inactive"},
                user_id=user.id,
            )
            raise ForbiddenException("Account is inactive. Please contact your system administrator.")

        # Success - reset counters
        user.failed_login_count = 0
        user.locked_until = None
        self.repository.update(user)

        # Create JWT access token
        access_token = create_access_token(
            subject=str(user.id),
            role=user.role.value,
        )

        self.audit_service.log_action(
            action="login_success",
            detail={"email": clean_email, "role": user.role.value},
            user_id=user.id,
        )

        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            user=UserRead.model_validate(user),
        )

    def register_user(
        self,
        user_in: UserCreate,
        creator: Optional[User] = None,
    ) -> UserRead:
        """Register a new user account with hashed password."""
        clean_email = user_in.email.strip().lower()
        existing = self.repository.get_by_email(clean_email)
        if existing:
            raise ConflictException(f"User with email '{clean_email}' already exists.")

        validate_password_strength(user_in.password)
        hashed_password = get_password_hash(user_in.password)

        new_user = User(
            name=user_in.name.strip(),
            email=clean_email,
            password_hash=hashed_password,
            role=user_in.role,
            is_active=True,
            failed_login_count=0,
            locked_until=None,
        )
        created = self.repository.create(new_user)

        self.audit_service.log_action(
            action="user_created",
            detail={
                "email": created.email,
                "role": created.role.value,
                "created_by": str(creator.id) if creator else "bootstrap",
            },
            user_id=creator.id if creator else created.id,
        )

        return UserRead.model_validate(created)

    def get_user_by_id(self, user_id: uuid.UUID) -> Optional[UserRead]:
        """Fetch user by ID."""
        user = self.repository.get_by_id(user_id)
        if not user:
            return None
        return UserRead.model_validate(user)

    def list_users(self, limit: int = 100, offset: int = 0) -> List[UserRead]:
        """List all users with pagination."""
        users = self.repository.list_all(limit=limit, offset=offset)
        return [UserRead.model_validate(u) for u in users]

    def update_user(
        self,
        user_id: uuid.UUID,
        user_update: UserUpdate,
        admin_user: User,
    ) -> UserRead:
        """Update user role, name, or activation state (admin only)."""
        user = self.repository.get_by_id(user_id)
        if not user:
            raise NotFoundException("User", user_id)

        changes: Dict[str, Any] = {}
        if user_update.name is not None and user_update.name != user.name:
            changes["name"] = {"old": user.name, "new": user_update.name}
            user.name = user_update.name

        if user_update.role is not None and user_update.role != user.role:
            changes["role"] = {"old": user.role.value, "new": user_update.role.value}
            user.role = user_update.role

        if user_update.is_active is not None and user_update.is_active != user.is_active:
            changes["is_active"] = {"old": user.is_active, "new": user_update.is_active}
            user.is_active = user_update.is_active

        if changes:
            self.repository.update(user)
            self.audit_service.log_action(
                action="user_updated",
                detail={
                    "target_user_id": str(user.id),
                    "email": user.email,
                    "changes": changes,
                    "updated_by": str(admin_user.id),
                },
                user_id=admin_user.id,
            )

        return UserRead.model_validate(user)

    def bootstrap_admin(
        self,
        name: str = "System Administrator",
        email: str = "admin@secassess.local",
        password: str = "AdminSecurePassword123!",
    ) -> Optional[UserRead]:
        """Bootstrap initial admin user if no admin exists in the system."""
        admin_count = self.repository.count_by_role(UserRole.ADMIN)
        if admin_count > 0:
            return None

        # Check if email is already taken
        existing = self.repository.get_by_email(email)
        if existing:
            existing.role = UserRole.ADMIN
            self.repository.update(existing)
            return UserRead.model_validate(existing)

        admin_in = UserCreate(
            name=name,
            email=email,
            password=password,
            role=UserRole.ADMIN,
        )
        return self.register_user(admin_in, creator=None)
