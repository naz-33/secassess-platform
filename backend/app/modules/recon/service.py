import uuid
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from app.modules.recon.models import Asset, AssetType
from app.modules.recon.repository import ReconRepository
from app.modules.recon.schemas import AssetRead


class ReconService:
    """Public business logic service for reconnaissance assets and cataloging."""

    def __init__(self, db: Session):
        self.db = db
        self.repository = ReconRepository(db)

    def create_assets_from_scan(
        self,
        assessment_id: uuid.UUID,
        scan_id: uuid.UUID,
        parsed_items: List[Dict[str, Any]],
    ) -> List[AssetRead]:
        """
        Store discovered assets resulting from a completed scan.
        """
        asset_objs: List[Asset] = []
        for item in parsed_items:
            t_str = str(item.get("type", "host")).lower()
            try:
                asset_type = AssetType(t_str)
            except ValueError:
                asset_type = AssetType.HOST

            asset_objs.append(
                Asset(
                    assessment_id=assessment_id,
                    scan_id=scan_id,
                    type=asset_type,
                    value=str(item.get("value", "")),
                    details=item.get("details", {}),
                )
            )

        created = self.repository.bulk_create(asset_objs)
        return [AssetRead.model_validate(a) for a in created]

    def list_assets(
        self,
        assessment_id: uuid.UUID,
        asset_type: Optional[str] = None,
        scan_id: Optional[uuid.UUID] = None,
    ) -> List[AssetRead]:
        """
        List all discovered assets for an assessment with optional filtering.
        """
        filter_type: Optional[AssetType] = None
        if asset_type:
            try:
                filter_type = AssetType(asset_type.lower())
            except ValueError:
                return []

        assets = self.repository.list_by_assessment(
            assessment_id=assessment_id,
            asset_type=filter_type,
            scan_id=scan_id,
        )
        return [AssetRead.model_validate(a) for a in assets]

    def get_asset_summary(self, assessment_id: uuid.UUID) -> Dict[str, Any]:
        """Return aggregated asset counts by type and open ports/services."""
        return self.repository.get_summary(assessment_id)

