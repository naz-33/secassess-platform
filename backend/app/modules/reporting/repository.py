import uuid
from typing import List, Optional
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from app.modules.reporting.models import Report, ReportStatus


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

    def update(self, report: Report) -> Report:
        self.db.add(report)
        self.db.commit()
        self.db.refresh(report)
        return report

    def delete(self, report: Report) -> None:
        self.db.delete(report)
        self.db.commit()

    def list_by_assessment(self, assessment_id: uuid.UUID) -> List[Report]:
        return list(
            self.db.execute(
                select(Report)
                .where(Report.assessment_id == assessment_id)
                .order_by(Report.version.desc())
            ).scalars().all()
        )

    def get_latest_by_assessment(self, assessment_id: uuid.UUID) -> Optional[Report]:
        return self.db.execute(
            select(Report)
            .where(Report.assessment_id == assessment_id)
            .order_by(Report.version.desc())
            .limit(1)
        ).scalar_one_or_none()

    def get_next_version(self, assessment_id: uuid.UUID) -> int:
        max_ver = self.db.execute(
            select(func.max(Report.version)).where(Report.assessment_id == assessment_id)
        ).scalar()
        return (max_ver or 0) + 1

    def has_pending_report(self, assessment_id: uuid.UUID) -> bool:
        pending = self.db.execute(
            select(func.count(Report.id)).where(
                Report.assessment_id == assessment_id,
                Report.status == ReportStatus.PENDING,
            )
        ).scalar()
        return bool(pending and pending > 0)
