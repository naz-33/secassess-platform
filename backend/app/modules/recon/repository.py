import uuid
from typing import List, Optional, Dict, Any
from sqlalchemy import select, func, or_
from sqlalchemy.orm import Session, selectinload
from app.modules.recon.models import Asset, AssetDiscovery, AssetType


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

    def bulk_upsert_discovered(self, assets: List[Asset]) -> List[Asset]:
        """Create canonical assets and retain each scan's discovery association."""
        if not assets:
            return []

        canonical: Dict[tuple[AssetType, str], Asset] = {}
        for candidate in assets:
            key = (candidate.type, candidate.value)
            asset = canonical.get(key)
            if asset is None:
                asset = self.db.execute(
                    select(Asset)
                    .options(selectinload(Asset.discoveries))
                    .where(
                        Asset.assessment_id == candidate.assessment_id,
                        Asset.type == candidate.type,
                        Asset.value == candidate.value,
                    )
                    .order_by(Asset.created_at.asc())
                    .limit(1)
                ).scalar_one_or_none()
                if asset is None:
                    asset = candidate
                    self.db.add(asset)
                canonical[key] = asset

            if candidate.scan_id is not None:
                known_scan_ids = {discovery.scan_id for discovery in asset.discoveries}
                if candidate.scan_id not in known_scan_ids:
                    asset.discoveries.append(
                        AssetDiscovery(
                            scan_id=candidate.scan_id,
                            details=candidate.details or {},
                        )
                    )

        self.db.flush()
        self.db.commit()
        results = list(canonical.values())
        for asset in results:
            self.db.refresh(asset)
        return results

    def list_by_assessment(
        self,
        assessment_id: uuid.UUID,
        asset_type: Optional[AssetType] = None,
        scan_id: Optional[uuid.UUID] = None,
    ) -> List[Asset]:
        query = (
            select(Asset)
            .options(selectinload(Asset.discoveries))
            .where(Asset.assessment_id == assessment_id)
        )
        if asset_type:
            query = query.where(Asset.type == asset_type)
        if scan_id:
            query = query.where(
                or_(
                    Asset.scan_id == scan_id,
                    Asset.discoveries.any(AssetDiscovery.scan_id == scan_id),
                )
            )
        query = query.order_by(Asset.created_at.desc())
        return list(self.db.execute(query).unique().scalars().all())

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
