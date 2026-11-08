import uuid
from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.modules.reporting.models import Report


class ReportRepository:
    """Repository handling database operations for generated reports."""

    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, report_id: uuid.UUID) -> Optional[Report]:
        return self.db.execute(select(Report).where(Report.id == report_id)).scalar_one_or_none()

    def create(self, report: Report) -> Report:
        self.db.add(report)
        self.db.commit()
        self.db.refresh(report)
        return report

    def list_by_assessment(self, assessment_id: uuid.UUID) -> List[Report]:
        return list(
            self.db.execute(
                select(Report).where(Report.assessment_id == assessment_id).order_by(Report.generated_at.desc())
            ).scalars().all()
        )
