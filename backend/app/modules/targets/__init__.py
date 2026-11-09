"""Public API for Targets module."""
from app.modules.targets.service import TargetService
from app.modules.targets.scope_manager import ScopeManager, validate_scope, is_asset_in_scope
from app.modules.targets.schemas import (
    TargetCreate,
    TargetRead,
    TargetUpdate,
    ScopeItemCreate,
    ScopeItemRead,
)

__all__ = [
    "TargetService",
    "ScopeManager",
    "validate_scope",
    "is_asset_in_scope",
    "TargetCreate",
    "TargetRead",
    "TargetUpdate",
    "ScopeItemCreate",
    "ScopeItemRead",
]
