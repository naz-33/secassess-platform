import uuid
from typing import Optional, List
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.modules.auth.models import User


class UserRepository:
    """Repository handling database operations for the users table."""

    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, user_id: uuid.UUID) -> Optional[User]:
        return self.db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()

    def get_by_email(self, email: str) -> Optional[User]:
        return self.db.execute(select(User).where(User.email == email)).scalar_one_or_none()

    def create(self, user: User) -> User:
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def list_all(self, limit: int = 100, offset: int = 0) -> List[User]:
        return list(self.db.execute(select(User).limit(limit).offset(offset)).scalars().all())
