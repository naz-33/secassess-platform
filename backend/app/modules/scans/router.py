import uuid
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.exceptions import NotFoundException
from app.modules.auth import User
from app.modules.scans.schemas import ScanRead
from app.modules.scans.service import ScanService

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("/{scan_id}", response_model=ScanRead, status_code=status.HTTP_200_OK)
def get_scan(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScanRead:
    """Retrieve details and raw output of a specific scan."""
    service = ScanService(db)
    scan = service.get_scan(scan_id)
    if not scan:
        raise NotFoundException(resource="Scan", identifier=scan_id)
    return scan
