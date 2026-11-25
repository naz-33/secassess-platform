import uuid
from typing import List, Optional
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundException
from app.modules.audit import AuditService
from app.modules.targets.models import Target, ScopeItem
from app.modules.targets.repository import TargetRepository
from app.modules.targets.scope_manager import ScopeManager
from app.modules.targets.schemas import (
    TargetCreate,
    TargetRead,
    TargetUpdate,
    ScopeItemCreate,
    ScopeItemRead,
    ScopeValidationResponse,
)


class TargetService:
    """Public service API for Target and Scope management."""

    def __init__(self, db: Session):
        self.db = db
        self.repository = TargetRepository(db)
        self.scope_manager = ScopeManager(db)
        self.audit_service = AuditService(db)

    def assert_in_scope(self, target_id: uuid.UUID, asset: str) -> bool:
        """
        Public boundary method: verify asset scope.
        Must be invoked by all scanner/recon services before running scans.
        """
        return self.scope_manager.assert_in_scope(target_id, asset)

    def check_scope(
        self,
        target_id: uuid.UUID,
        asset: str,
        *,
        user_id: uuid.UUID,
    ) -> ScopeValidationResponse:
        """Evaluate asset scope returning diagnostic reason without raising exception."""
        in_scope, reason = self.scope_manager.check_scope(target_id, asset)
        self.audit_service.log_action(
            action="scope_validated",
            detail={
                "target_id": str(target_id),
                "asset": asset,
                "in_scope": in_scope,
                "reason": reason,
            },
            user_id=user_id,
        )
        return ScopeValidationResponse(
            asset=asset,
            target_id=target_id,
            in_scope=in_scope,
            reason=reason,
        )

    def create_target(
        self,
        target_in: TargetCreate,
        *,
        user_id: uuid.UUID,
    ) -> TargetRead:
        """Register a new assessment target with optional initial scope boundaries."""
        target = Target(
            name=target_in.name,
            base_url=target_in.base_url,
            description=target_in.description,
            authorization_note=target_in.authorization_note,
        )

        if target_in.scope_items:
            for item_in in target_in.scope_items:
                target.scope_items.append(
                    ScopeItem(
                        asset=item_in.asset,
                        in_scope=item_in.in_scope,
                        notes=item_in.notes,
                    )
                )

        created = self.repository.create(target)
        self.audit_service.log_action(
            action="target_created",
            detail={
                "target_id": str(created.id),
                "name": created.name,
                "base_url": created.base_url,
                "scope_items_count": len(created.scope_items),
            },
            user_id=user_id,
        )
        return TargetRead.model_validate(created)

    def get_target(self, target_id: uuid.UUID) -> Optional[TargetRead]:
        """Retrieve target details and configured scope items."""
        target = self.repository.get_by_id(target_id)
        if not target:
            return None
        return TargetRead.model_validate(target)

    def list_targets(self, limit: int = 100, offset: int = 0) -> List[TargetRead]:
        """List registered targets."""
        targets = self.repository.list_all(limit=limit, offset=offset)
        return [TargetRead.model_validate(t) for t in targets]

    def update_target(
        self,
        target_id: uuid.UUID,
        target_in: TargetUpdate,
        *,
        user_id: uuid.UUID,
    ) -> Optional[TargetRead]:
        """Update target metadata."""
        target = self.repository.get_by_id(target_id)
        if not target:
            return None

        update_data = target_in.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            setattr(target, key, value)

        updated = self.repository.update(target)
        self.audit_service.log_action(
            action="target_updated",
            detail={
                "target_id": str(updated.id),
                "updated_fields": sorted(update_data.keys()),
            },
            user_id=user_id,
        )
        return TargetRead.model_validate(updated)

    def delete_target(self, target_id: uuid.UUID, *, user_id: uuid.UUID) -> bool:
        """Delete target and cascade delete all its scope items."""
        target = self.repository.get_by_id(target_id)
        if not target:
            return False
        target_name = target.name
        base_url = target.base_url
        self.repository.delete(target)
        self.audit_service.log_action(
            action="target_deleted",
            detail={
                "target_id": str(target_id),
                "name": target_name,
                "base_url": base_url,
            },
            user_id=user_id,
        )
        return True

    def add_scope_item(
        self,
        target_id: uuid.UUID,
        scope_item_in: ScopeItemCreate,
        *,
        user_id: uuid.UUID,
    ) -> ScopeItemRead:
        """Add a scope boundary rule to an existing target."""
        target = self.repository.get_by_id(target_id)
        if not target:
            raise NotFoundException(resource="Target", identifier=target_id)

        scope_item = ScopeItem(
            target_id=target_id,
            asset=scope_item_in.asset,
            in_scope=scope_item_in.in_scope,
            notes=scope_item_in.notes,
        )
        created = self.repository.add_scope_item(scope_item)
        self.audit_service.log_action(
            action="scope_item_added",
            detail={
                "target_id": str(target_id),
                "scope_item_id": str(created.id),
                "asset": created.asset,
                "in_scope": created.in_scope,
            },
            user_id=user_id,
        )
        return ScopeItemRead.model_validate(created)

    def list_scope_items(self, target_id: uuid.UUID) -> List[ScopeItemRead]:
        """Retrieve all scope items defined for a target."""
        target = self.repository.get_by_id(target_id)
        if not target:
            raise NotFoundException(resource="Target", identifier=target_id)

        items = self.repository.get_scope_items_by_target(target_id)
        return [ScopeItemRead.model_validate(item) for item in items]

    def delete_scope_item(
        self,
        target_id: uuid.UUID,
        scope_item_id: uuid.UUID,
        *,
        user_id: uuid.UUID,
    ) -> bool:
        """Remove a specific scope item from a target."""
        item = self.repository.get_scope_item_by_id(scope_item_id)
        if not item or item.target_id != target_id:
            return False
        asset = item.asset
        in_scope = item.in_scope
        self.repository.delete_scope_item(item)
        self.audit_service.log_action(
            action="scope_item_deleted",
            detail={
                "target_id": str(target_id),
                "scope_item_id": str(scope_item_id),
                "asset": asset,
                "in_scope": in_scope,
            },
            user_id=user_id,
        )
        return True
