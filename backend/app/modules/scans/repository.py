import uuid
from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.modules.scans.models import Scan


class ScanRepository:
    """Repository handling database operations for scans."""

    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, scan_id: uuid.UUID) -> Optional[Scan]:
        return self.db.execute(select(Scan).where(Scan.id == scan_id)).scalar_one_or_none()

    def create(self, scan: Scan) -> Scan:
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def update(self, scan: Scan) -> Scan:
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def list_by_assessment(self, assessment_id: uuid.UUID) -> List[Scan]:
        return list(
            self.db.execute(
                select(Scan).where(Scan.assessment_id == assessment_id).order_by(Scan.started_at.desc())
            ).scalars().all()
        )
