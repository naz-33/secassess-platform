import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy import select, func, and_
from sqlalchemy.orm import Session
from app.modules.ai_analysis.models import (
    AIAnalysis,
    AIFunction,
    AIAnalysisStatus,
    AIReviewStatus,
)


class AIAnalysisRepository:
    """Repository handling database operations for AI analyses."""

    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, analysis_id: uuid.UUID) -> Optional[AIAnalysis]:
        return self.db.execute(
            select(AIAnalysis).where(AIAnalysis.id == analysis_id)
        ).scalar_one_or_none()

    def create(self, analysis: AIAnalysis) -> AIAnalysis:
        self.db.add(analysis)
        self.db.commit()
        self.db.refresh(analysis)
        return analysis

    def update(self, analysis: AIAnalysis) -> AIAnalysis:
        self.db.commit()
        self.db.refresh(analysis)
        return analysis

    def list_by_assessment(
        self,
        assessment_id: uuid.UUID,
        function: Optional[AIFunction] = None,
        status: Optional[AIAnalysisStatus] = None,
        review_status: Optional[AIReviewStatus] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AIAnalysis]:
        stmt = select(AIAnalysis).where(AIAnalysis.assessment_id == assessment_id)
        if function:
            stmt = stmt.where(AIAnalysis.function == function)
        if status:
            stmt = stmt.where(AIAnalysis.status == status)
        if review_status:
            stmt = stmt.where(AIAnalysis.review_status == review_status)

        stmt = stmt.order_by(AIAnalysis.created_at.desc()).limit(limit).offset(offset)
        return list(self.db.execute(stmt).scalars().all())

    def find_cached_analysis(
        self,
        assessment_id: uuid.UUID,
        function: AIFunction,
        input_hash: str,
        prompt_version: str,
    ) -> Optional[AIAnalysis]:
        """Find prior completed analysis with identical input_hash and prompt_version."""
        stmt = select(AIAnalysis).where(
            and_(
                AIAnalysis.assessment_id == assessment_id,
                AIAnalysis.function == function,
                AIAnalysis.input_hash == input_hash,
                AIAnalysis.prompt_version == prompt_version,
                AIAnalysis.status == AIAnalysisStatus.COMPLETED,
            )
        ).order_by(AIAnalysis.created_at.desc())
        return self.db.execute(stmt).scalars().first()

    def count_calls_for_assessment(self, assessment_id: uuid.UUID) -> int:
        """Count total AI analysis invocations (pending or completed) for an assessment."""
        stmt = select(func.count(AIAnalysis.id)).where(AIAnalysis.assessment_id == assessment_id)
        return self.db.execute(stmt).scalar() or 0

    def count_calls_for_user_since(self, user_id: uuid.UUID, since: datetime) -> int:
        """Count total AI analysis requests initiated by a user within a time window."""
        stmt = select(func.count(AIAnalysis.id)).where(
            and_(
                AIAnalysis.requested_by == user_id,
                AIAnalysis.created_at >= since,
            )
        )
        return self.db.execute(stmt).scalar() or 0

    def get_summary(self, assessment_id: uuid.UUID) -> Dict[str, Any]:
        """Aggregate counts of analyses by function, status, review status, and approved summary."""
        func_counts_raw = dict(
            self.db.execute(
                select(AIAnalysis.function, func.count(AIAnalysis.id))
                .where(AIAnalysis.assessment_id == assessment_id)
                .group_by(AIAnalysis.function)
            ).all()
        )
        status_counts_raw = dict(
            self.db.execute(
                select(AIAnalysis.status, func.count(AIAnalysis.id))
                .where(AIAnalysis.assessment_id == assessment_id)
                .group_by(AIAnalysis.status)
            ).all()
        )
        approved_count = self.db.execute(
            select(func.count(AIAnalysis.id)).where(
                AIAnalysis.assessment_id == assessment_id,
                AIAnalysis.review_status == AIReviewStatus.APPROVED,
            )
        ).scalar() or 0

        has_approved_summary = bool(
            self.db.execute(
                select(func.count(AIAnalysis.id)).where(
                    AIAnalysis.assessment_id == assessment_id,
                    AIAnalysis.function == AIFunction.SUMMARIZE,
                    AIAnalysis.status == AIAnalysisStatus.COMPLETED,
                    AIAnalysis.review_status == AIReviewStatus.APPROVED,
                )
            ).scalar()
        )

        by_function = {f.value: func_counts_raw.get(f, 0) for f in AIFunction}
        by_status = {s.value: status_counts_raw.get(s, 0) for s in AIAnalysisStatus}

        return {
            "total": sum(by_status.values()),
            "by_function": by_function,
            "by_status": by_status,
            "approved_count": approved_count,
            "has_approved_executive_summary": has_approved_summary,
        }

    def get_latest_approved_summary(self, assessment_id: uuid.UUID) -> Optional[AIAnalysis]:
        """Fetch the most recently approved executive summary."""
        stmt = (
            select(AIAnalysis)
            .where(
                AIAnalysis.assessment_id == assessment_id,
                AIAnalysis.function == AIFunction.SUMMARIZE,
                AIAnalysis.status == AIAnalysisStatus.COMPLETED,
                AIAnalysis.review_status == AIReviewStatus.APPROVED,
            )
            .order_by(AIAnalysis.reviewed_at.desc(), AIAnalysis.created_at.desc())
        )
        return self.db.execute(stmt).scalars().first()

