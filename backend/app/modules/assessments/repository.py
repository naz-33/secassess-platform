import uuid
from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.modules.assessments.models import Assessment


class AssessmentRepository:
    """Repository handling database operations for assessments."""

    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, assessment_id: uuid.UUID) -> Optional[Assessment]:
        return self.db.execute(
            select(Assessment).where(Assessment.id == assessment_id)
        ).scalar_one_or_none()

    def get_by_id_for_update(self, assessment_id: uuid.UUID) -> Optional[Assessment]:
        stmt = select(Assessment).where(Assessment.id == assessment_id)
        if self.db.bind and self.db.bind.dialect.name != "sqlite":
            stmt = stmt.with_for_update()
        return self.db.execute(stmt).scalar_one_or_none()

    def create(self, assessment: Assessment) -> Assessment:
        self.db.add(assessment)
        self.db.commit()
        self.db.refresh(assessment)
        return assessment

    def list_all(self, limit: int = 100, offset: int = 0) -> List[Assessment]:
        return list(
            self.db.execute(
                select(Assessment).order_by(Assessment.created_at.desc()).limit(limit).offset(offset)
            ).scalars().all()
        )

