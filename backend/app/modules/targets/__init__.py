"""Public API for Targets module."""
from app.modules.targets.service import TargetService
from app.modules.targets.scope_manager import ScopeManager

__all__ = ["TargetService", "ScopeManager"]
