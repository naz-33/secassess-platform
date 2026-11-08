import uuid
from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.modules.verification.models import Verification


class VerificationRepository:
    """Repository handling database operations for finding verifications."""

    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, verification_id: uuid.UUID) -> Optional[Verification]:
        return self.db.execute(
            select(Verification).where(Verification.id == verification_id)
        ).scalar_one_or_none()

    def create(self, verification: Verification) -> Verification:
        self.db.add(verification)
        self.db.commit()
        self.db.refresh(verification)
        return verification

    def list_by_finding(self, finding_id: uuid.UUID) -> List[Verification]:
        return list(
            self.db.execute(
                select(Verification).where(Verification.finding_id == finding_id).order_by(Verification.verified_at.desc())
            ).scalars().all()
        )
