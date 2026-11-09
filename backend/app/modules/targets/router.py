import uuid
from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user, require_roles
from app.core.exceptions import NotFoundException
from app.modules.auth import User
from app.modules.targets.service import TargetService
from app.modules.targets.schemas import (
    TargetCreate,
    TargetRead,
    TargetUpdate,
    ScopeItemCreate,
    ScopeItemRead,
    ScopeValidationRequest,
    ScopeValidationResponse,
)

router = APIRouter(prefix="/targets", tags=["targets"])


@router.post("", response_model=TargetRead, status_code=status.HTTP_201_CREATED)
@router.post("/", response_model=TargetRead, status_code=status.HTTP_201_CREATED, include_in_schema=False)
def create_target(
    target_in: TargetCreate,
    current_user: User = Depends(require_roles("assessor", "admin")),
    db: Session = Depends(get_db),
) -> TargetRead:
    """Create a new authorized assessment target with scope boundaries."""
    service = TargetService(db)
    return service.create_target(target_in)


@router.get("", response_model=List[TargetRead])
@router.get("/", response_model=List[TargetRead], include_in_schema=False)
def list_targets(
    limit: int = 100,
    offset: int = 0,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[TargetRead]:
    """List all registered assessment targets."""
    service = TargetService(db)
    return service.list_targets(limit=limit, offset=offset)


@router.get("/{target_id}", response_model=TargetRead)
def get_target(
    target_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> TargetRead:
    """Retrieve an assessment target by ID with configured scope items."""
    service = TargetService(db)
    target = service.get_target(target_id)
    if not target:
        raise NotFoundException(resource="Target", identifier=target_id)
    return target


@router.patch("/{target_id}", response_model=TargetRead)
def update_target(
    target_id: uuid.UUID,
    target_in: TargetUpdate,
    current_user: User = Depends(require_roles("assessor", "admin")),
    db: Session = Depends(get_db),
) -> TargetRead:
    """Update assessment target metadata."""
    service = TargetService(db)
    target = service.update_target(target_id, target_in)
    if not target:
        raise NotFoundException(resource="Target", identifier=target_id)
    return target


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(
    target_id: uuid.UUID,
    current_user: User = Depends(require_roles("assessor", "admin")),
    db: Session = Depends(get_db),
) -> None:
    """Delete an assessment target and associated scope items."""
    service = TargetService(db)
    success = service.delete_target(target_id)
    if not success:
        raise NotFoundException(resource="Target", identifier=target_id)


@router.get("/{target_id}/scope", response_model=List[ScopeItemRead])
@router.get("/{target_id}/scope/", response_model=List[ScopeItemRead], include_in_schema=False)
def get_target_scope(
    target_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[ScopeItemRead]:
    """Retrieve all scope items defined for a target."""
    service = TargetService(db)
    return service.list_scope_items(target_id)


@router.post("/{target_id}/scope", response_model=ScopeItemRead, status_code=status.HTTP_201_CREATED)
@router.post("/{target_id}/scope/", response_model=ScopeItemRead, status_code=status.HTTP_201_CREATED, include_in_schema=False)
def add_target_scope_item(
    target_id: uuid.UUID,
    scope_in: ScopeItemCreate,
    current_user: User = Depends(require_roles("assessor", "admin")),
    db: Session = Depends(get_db),
) -> ScopeItemRead:
    """Add a new scope boundary rule (asset URL, host, IP, or CIDR) to a target."""
    service = TargetService(db)
    return service.add_scope_item(target_id, scope_in)


@router.delete("/{target_id}/scope/{scope_item_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target_scope_item(
    target_id: uuid.UUID,
    scope_item_id: uuid.UUID,
    current_user: User = Depends(require_roles("assessor", "admin")),
    db: Session = Depends(get_db),
) -> None:
    """Remove a specific scope item from a target."""
    service = TargetService(db)
    success = service.delete_scope_item(target_id, scope_item_id)
    if not success:
        raise NotFoundException(resource="ScopeItem", identifier=scope_item_id)


@router.post("/{target_id}/scope/validate", response_model=ScopeValidationResponse)
def validate_asset_scope(
    target_id: uuid.UUID,
    validation_req: ScopeValidationRequest,
    current_user: User = Depends(require_roles("assessor", "admin")),
    db: Session = Depends(get_db),
) -> ScopeValidationResponse:
    """
    Validate whether a candidate asset is authorized under the target's scope rules.
    Returns status and diagnostic explanation.
    """
    service = TargetService(db)
    return service.check_scope(target_id, validation_req.asset)
