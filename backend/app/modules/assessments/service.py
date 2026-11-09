import uuid
from typing import List, Optional
from sqlalchemy.orm import Session
from app.core.exceptions import NotFoundException
from app.modules.targets import TargetService
from app.modules.audit import AuditService
from app.modules.assessments.models import Assessment
from app.modules.assessments.repository import AssessmentRepository
from app.modules.assessments.schemas import AssessmentCreate, AssessmentRead


class AssessmentService:
    """Public business logic service for security assessment lifecycles."""

    def __init__(self, db: Session):
        self.db = db
        self.repository = AssessmentRepository(db)
        self.target_service = TargetService(db)
        self.audit_service = AuditService(db)

    def create_assessment(
        self,
        assessment_in: AssessmentCreate,
        user_id: Optional[uuid.UUID] = None,
    ) -> AssessmentRead:
        """Create a new security assessment cycle after verifying the target exists."""
        target = self.target_service.get_target(assessment_in.target_id)
        if not target:
            raise NotFoundException("Target", assessment_in.target_id)

        effective_user_id = user_id or assessment_in.created_by

        assessment = Assessment(
            name=assessment_in.name,
            target_id=assessment_in.target_id,
            status=assessment_in.status,
            created_by=effective_user_id,
        )
        created = self.repository.create(assessment)

        # Audit log creation
        self.audit_service.log_action(
            action="assessment_created",
            detail={
                "assessment_id": str(created.id),
                "name": created.name,
                "target_id": str(created.target_id),
            },
            user_id=effective_user_id,
        )

        return AssessmentRead.model_validate(created)

    def get_assessment(self, assessment_id: uuid.UUID) -> Optional[AssessmentRead]:
        """Fetch assessment by ID."""
        assessment = self.repository.get_by_id(assessment_id)
        if not assessment:
            return None
        return AssessmentRead.model_validate(assessment)

    def list_assessments(self, limit: int = 100, offset: int = 0) -> List[AssessmentRead]:
        """List assessments ordered by creation date."""
        records = self.repository.list_all(limit=limit, offset=offset)
        return [AssessmentRead.model_validate(a) for a in records]
