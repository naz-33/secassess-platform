import uuid
from typing import List, Optional, Dict, Any
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from app.modules.recon.models import Asset, AssetType


class ReconRepository:
    """Repository handling database operations for discovered recon assets."""

    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, asset_id: uuid.UUID) -> Optional[Asset]:
        return self.db.execute(select(Asset).where(Asset.id == asset_id)).scalar_one_or_none()

    def create(self, asset: Asset) -> Asset:
        self.db.add(asset)
        self.db.commit()
        self.db.refresh(asset)
        return asset

    def bulk_create(self, assets: List[Asset]) -> List[Asset]:
        if not assets:
            return []
        self.db.add_all(assets)
        self.db.commit()
        for a in assets:
            self.db.refresh(a)
        return assets

    def list_by_assessment(
        self,
        assessment_id: uuid.UUID,
        asset_type: Optional[AssetType] = None,
        scan_id: Optional[uuid.UUID] = None,
    ) -> List[Asset]:
        query = select(Asset).where(Asset.assessment_id == assessment_id)
        if asset_type:
            query = query.where(Asset.type == asset_type)
        if scan_id:
            query = query.where(Asset.scan_id == scan_id)
        query = query.order_by(Asset.created_at.desc())
        return list(self.db.execute(query).scalars().all())

    def get_summary(self, assessment_id: uuid.UUID) -> Dict[str, Any]:
        """Aggregate counts by asset type and return list of open ports/services."""
        counts = dict(
            self.db.execute(
                select(Asset.type, func.count(Asset.id))
                .where(Asset.assessment_id == assessment_id)
                .group_by(Asset.type)
            ).all()
        )
        by_type = {t.value: counts.get(t, 0) for t in AssetType}

        open_ports_and_services = []
        rows = list(
            self.db.execute(
                select(Asset.type, Asset.value, Asset.details)
                .where(
                    Asset.assessment_id == assessment_id,
                    Asset.type.in_([AssetType.PORT, AssetType.SERVICE]),
                )
                .order_by(Asset.value.asc())
                .limit(20)
            ).all()
        )
        for t, val, details in rows:
            open_ports_and_services.append({
                "type": t.value if hasattr(t, "value") else str(t),
                "value": val,
                "details": details or {},
            })

        return {
            "by_type": by_type,
            "total": sum(by_type.values()),
            "open_ports_and_services": open_ports_and_services,
        }

