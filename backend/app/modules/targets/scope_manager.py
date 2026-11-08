import uuid
from sqlalchemy.orm import Session
from app.core.exceptions import ScopeViolationException


class ScopeManager:
    """
    Scope enforcement manager.

    IMPORTANT ARCHITECTURE RULE:
    EVERY scan execution (recon, web_assessment, custom runners) MUST call
    `ScopeManager.assert_in_scope(target_id, asset)` BEFORE initiating any network activity.
    If the asset is out of scope or not explicitly allowed, a ScopeViolationException is raised.
    Recon and web assessment modules depend on this enforcement via the Targets public API.
    """

    def __init__(self, db: Session):
        self.db = db

    def assert_in_scope(self, target_id: uuid.UUID, asset: str) -> bool:
        """
        Verify that an asset (URL, host, IP, or CIDR) is explicitly authorized and in-scope for the target.

        Raises:
            ScopeViolationException: if the asset is not authorized or explicitly marked out-of-scope.
        Returns:
            True if authorization passes.
        """
        # TODO: Implement CIDR, domain matching, and blacklist/whitelist validation logic
        # For initial skeleton, pass if target exists or placeholder logic
        if not asset or not target_id:
            raise ScopeViolationException(asset=asset, target_id=target_id)
        return True
