import uuid
from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload
from app.modules.targets.models import Target, ScopeItem


class TargetRepository:
    """Repository handling database operations for targets and scope_items."""

    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, target_id: uuid.UUID) -> Optional[Target]:
        return self.db.execute(
            select(Target).options(selectinload(Target.scope_items)).where(Target.id == target_id)
        ).scalar_one_or_none()

    def get_by_name(self, name: str) -> Optional[Target]:
        return self.db.execute(
            select(Target).options(selectinload(Target.scope_items)).where(Target.name == name)
        ).scalar_one_or_none()

    def create(self, target: Target) -> Target:
        self.db.add(target)
        self.db.commit()
        self.db.refresh(target)
        return target

    def update(self, target: Target) -> Target:
        self.db.commit()
        self.db.refresh(target)
        return target

    def delete(self, target: Target) -> None:
        self.db.delete(target)
        self.db.commit()

    def list_all(self, limit: int = 100, offset: int = 0) -> List[Target]:
        return list(
            self.db.execute(
                select(Target)
                .options(selectinload(Target.scope_items))
                .order_by(Target.created_at.desc())
                .limit(limit)
                .offset(offset)
            ).scalars().all()
        )

    def add_scope_item(self, scope_item: ScopeItem) -> ScopeItem:
        self.db.add(scope_item)
        self.db.commit()
        self.db.refresh(scope_item)
        return scope_item

    def get_scope_items_by_target(self, target_id: uuid.UUID) -> List[ScopeItem]:
        return list(
            self.db.execute(
                select(ScopeItem).where(ScopeItem.target_id == target_id)
            ).scalars().all()
        )

    def get_scope_item_by_id(self, scope_item_id: uuid.UUID) -> Optional[ScopeItem]:
        return self.db.execute(
            select(ScopeItem).where(ScopeItem.id == scope_item_id)
        ).scalar_one_or_none()

    def delete_scope_item(self, scope_item: ScopeItem) -> None:
        self.db.delete(scope_item)
        self.db.commit()
