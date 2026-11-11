"""Aggregated database model imports for Alembic migrations and Base metadata discovery."""

# Import Base
from app.core.database import Base

# Import all module models to ensure they register on Base.metadata
from app.modules.auth.models import User
from app.modules.audit.models import AuditLog
from app.modules.targets.models import Target, ScopeItem
from app.modules.assessments.models import Assessment
from app.modules.scans.models import Scan
from app.modules.recon.models import Asset, AssetDiscovery
from app.modules.findings.models import Finding, Evidence, SeverityChange
from app.modules.ai_analysis.models import AIAnalysis
from app.modules.verification.models import Verification
from app.modules.reporting.models import Report

__all__ = [
    "Base",
    "User",
    "AuditLog",
    "Target",
    "ScopeItem",
    "Assessment",
    "Scan",
    "Asset",
    "AssetDiscovery",
    "Finding",
    "Evidence",
    "SeverityChange",
    "AIAnalysis",
    "Verification",
    "Report",
]
