import uuid
from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload
from app.modules.findings.models import Finding, Evidence, FindingStatus, FindingSeverity


class FindingRepository:
    """Repository handling database operations for findings and evidence."""

    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, finding_id: uuid.UUID) -> Optional[Finding]:
        return self.db.execute(
            select(Finding).options(selectinload(Finding.evidences)).where(Finding.id == finding_id)
        ).scalar_one_or_none()

    def create(self, finding: Finding) -> Finding:
        self.db.add(finding)
        self.db.commit()
        self.db.refresh(finding)
        return finding

    def list_by_assessment(
        self,
        assessment_id: uuid.UUID,
        status: Optional[FindingStatus] = None,
        severity: Optional[FindingSeverity] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Finding]:
        query = select(Finding).options(selectinload(Finding.evidences)).where(Finding.assessment_id == assessment_id)
        if status:
            query = query.where(Finding.status == status)
        if severity:
            query = query.where(Finding.severity == severity)
        query = query.order_by(Finding.created_at.desc()).limit(limit).offset(offset)
        return list(self.db.execute(query).scalars().all())

    def add_evidence(self, evidence: Evidence) -> Evidence:
        self.db.add(evidence)
        self.db.commit()
        self.db.refresh(evidence)
        return evidence
