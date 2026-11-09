import uuid
from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user, require_roles
from app.modules.auth import User
from app.modules.verification.schemas import VerificationCreate, VerificationRead
from app.modules.verification.service import VerificationService

router = APIRouter(tags=["verification"])


@router.get(
    "/verification",
    status_code=status.HTTP_200_OK,
)
def get_verification_status(
    current_user: User = Depends(get_current_user),
):
    """Retrieve verification module status and information."""
    return {"status": "active", "module": "verification"}


@router.post(
    "/findings/{finding_id}/verify",
    response_model=VerificationRead,
    status_code=status.HTTP_201_CREATED,
)
def verify_finding(
    finding_id: uuid.UUID,
    verification_in: VerificationCreate,
    current_user: User = Depends(require_roles("assessor", "admin")),
    db: Session = Depends(get_db),
) -> VerificationRead:
    """Record an assessor verification decision (confirmed, false_positive, needs_testing)."""
    service = VerificationService(db)
    return service.verify_finding(
        finding_id=finding_id,
        verification_in=verification_in,
        user=current_user,
    )


@router.get(
    "/findings/{finding_id}/verifications",
    response_model=List[VerificationRead],
    status_code=status.HTTP_200_OK,
)
def get_finding_verifications(
    finding_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[VerificationRead]:
    """Retrieve full chronological verification history for a finding."""
    service = VerificationService(db)
    return service.list_verifications(finding_id)
