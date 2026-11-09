import uuid
from typing import Optional, List
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from app.modules.auth.models import User, UserRole


class UserRepository:
    """Repository handling database operations for the users table."""

    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, user_id: uuid.UUID) -> Optional[User]:
        return self.db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()

    def get_by_email(self, email: str) -> Optional[User]:
        clean = email.strip().lower()
        return self.db.execute(select(User).where(func.lower(User.email) == clean)).scalar_one_or_none()

    def create(self, user: User) -> User:
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def update(self, user: User) -> User:
        self.db.commit()
        self.db.refresh(user)
        return user

    def list_all(self, limit: int = 100, offset: int = 0) -> List[User]:
        stmt = select(User).order_by(User.created_at.desc()).limit(limit).offset(offset)
        return list(self.db.execute(stmt).scalars().all())

    def count_by_role(self, role: UserRole) -> int:
        stmt = select(func.count(User.id)).where(User.role == role)
        return self.db.execute(stmt).scalar_one() or 0
