import uuid
from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.modules.ai_analysis.models import AIAnalysis


class AIAnalysisRepository:
    """Repository handling database operations for AI analyses."""

    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, analysis_id: uuid.UUID) -> Optional[AIAnalysis]:
        return self.db.execute(select(AIAnalysis).where(AIAnalysis.id == analysis_id)).scalar_one_or_none()

    def create(self, analysis: AIAnalysis) -> AIAnalysis:
        self.db.add(analysis)
        self.db.commit()
        self.db.refresh(analysis)
        return analysis

    def list_by_finding(self, finding_id: uuid.UUID) -> List[AIAnalysis]:
        return list(
            self.db.execute(
                select(AIAnalysis).where(AIAnalysis.finding_id == finding_id).order_by(AIAnalysis.created_at.desc())
            ).scalars().all()
        )
