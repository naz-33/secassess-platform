import uuid
from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.modules.recon.models import Asset


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

    def list_by_assessment(self, assessment_id: uuid.UUID) -> List[Asset]:
        return list(
            self.db.execute(
                select(Asset).where(Asset.assessment_id == assessment_id).order_by(Asset.created_at.desc())
            ).scalars().all()
        )
