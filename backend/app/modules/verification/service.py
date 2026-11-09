import uuid
from typing import List
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    NotFoundException,
    ForbiddenException,
    UnprocessableEntityException,
)
from app.modules.audit import AuditService
from app.modules.auth import User
from app.modules.findings import FindingService, FindingStatus
from app.modules.verification.models import Verification, VerificationDecision
from app.modules.verification.repository import VerificationRepository
from app.modules.verification.schemas import VerificationCreate, VerificationRead


class VerificationService:
    """
    Public business logic service for assessor review and verification workflow.
    This service is the SOLE SANCTIONED PATH to set finding status to
    confirmed, false_positive, or needs_testing.
    """

    def __init__(self, db: Session):
        self.db = db
        self.repository = VerificationRepository(db)
        self.finding_service = FindingService(db)
        self.audit_service = AuditService(db)

    def verify_finding(
        self,
        finding_id: uuid.UUID,
        verification_in: VerificationCreate,
        user: User,
    ) -> VerificationRead:
        """
        Record assessor verification decision and transition finding status.
        Append-only: creates a new verification history row and updates the finding's current status.
        """
        user_role = user.role.value if hasattr(user.role, "value") else str(user.role)
        if user_role not in ("assessor", "admin"):
            raise ForbiddenException("Only assessors and administrators can verify findings.")

        finding = self.finding_service.get_finding(finding_id)
        if not finding:
            raise NotFoundException("Finding", finding_id)

        decision = verification_in.decision

        # Strict business rules
        if decision == VerificationDecision.CONFIRMED:
            if not verification_in.evidence_reviewed:
                raise UnprocessableEntityException(
                    "Confirmation requires explicit review of evidence (evidence_reviewed must be true)."
                )
            if not finding.evidences or len(finding.evidences) == 0:
                raise UnprocessableEntityException(
                    "Cannot confirm finding without at least one supporting evidence item."
                )
        elif decision in (VerificationDecision.FALSE_POSITIVE, VerificationDecision.NEEDS_TESTING):
            notes = (verification_in.notes or "").strip()
            if len(notes) < settings.MIN_VERIFICATION_NOTE_LENGTH:
                raise UnprocessableEntityException(
                    f"Decision '{decision.value}' requires explanatory notes of at least "
                    f"{settings.MIN_VERIFICATION_NOTE_LENGTH} characters."
                )

        # 1. Create append-only verification row
        verification = Verification(
            finding_id=finding_id,
            assessor_id=user.id,
            decision=decision,
            notes=verification_in.notes.strip() if verification_in.notes else None,
            evidence_reviewed=verification_in.evidence_reviewed,
        )
        created = self.repository.create(verification)

        # 2. Transition finding status via sanctioned internal method
        target_status = FindingStatus(decision.value)
        updated_finding, previous_status = self.finding_service.apply_verified_status(
            finding_id=finding_id,
            decision=target_status,
            assessor_id=user.id,
            verified_at=created.verified_at,
        )

        # 3. Record audit trail
        self.audit_service.log_action(
            action="verification_recorded",
            detail={
                "finding_id": str(finding_id),
                "decision": decision.value,
                "previous_status": previous_status,
                "evidence_reviewed": verification_in.evidence_reviewed,
                "has_notes": bool(verification_in.notes),
            },
            user_id=user.id,
        )

        return VerificationRead.model_validate(created)

    def list_verifications(self, finding_id: uuid.UUID) -> List[VerificationRead]:
        """List historical verifications for a finding in chronological order."""
        finding = self.finding_service.get_finding(finding_id)
        if not finding:
            raise NotFoundException("Finding", finding_id)

        history = self.repository.list_by_finding(finding_id)
        return [VerificationRead.model_validate(v) for v in history]
