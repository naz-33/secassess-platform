"""Public service API for scans and runner coordination."""
import logging
import uuid
from typing import List, Optional, Dict, Any
from fastapi import BackgroundTasks
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.modules.scans.repository import ScanRepository
from app.modules.scans.runner import ScanRunner
from app.modules.scans.schemas import ScanCreate, ScanRead

logger = logging.getLogger(__name__)


def _run_scan_background_worker(
    scan_id: uuid.UUID,
    argv: list[str] | list[list[str]],
    user_id: Optional[uuid.UUID] = None,
) -> None:
    """Background worker task executing scan subprocess in an isolated database session."""
    db = SessionLocal()
    try:
        runner = ScanRunner(db)
        runner.execute_scan(scan_id=scan_id, argv=argv, user_id=user_id)
    except Exception as exc:
        logger.exception("Error executing background scan %s: %s", scan_id, exc)
    finally:
        db.close()


class ScanService:
    """Public business logic service and background task entrypoint for scans."""

    def __init__(self, db: Session):
        self.db = db
        self.repository = ScanRepository(db)
        self.runner = ScanRunner(db)

    def trigger_scan(
        self,
        assessment_id: uuid.UUID,
        scan_in: ScanCreate,
        background_tasks: Optional[BackgroundTasks] = None,
        user_id: Optional[uuid.UUID] = None,
    ) -> ScanRead:
        """
        Validate target scope, initialize scan record, and enqueue background execution.

        Raises:
            NotFoundException: If assessment or target does not exist.
            ScopeViolationException (403): If target asset is out of scope.
            ValueError (422): If target or tool options are invalid.
        """
        scan, _, argv = self.runner.validate_and_prepare(
            assessment_id=assessment_id,
            tool=scan_in.tool.value,
            target=scan_in.target,
            options=scan_in.options,
            user_id=user_id,
        )

        if background_tasks is not None:
            background_tasks.add_task(
                _run_scan_background_worker,
                scan.id,
                argv,
                user_id,
            )
        else:
            # Synchronous execution fallback (e.g. tests or direct service calls)
            scan = self.runner.execute_scan(scan_id=scan.id, argv=argv, user_id=user_id)

        return ScanRead.model_validate(scan)

    def get_scan(self, scan_id: uuid.UUID) -> Optional[ScanRead]:
        """Retrieve scan status and raw output."""
        scan = self.repository.get_by_id(scan_id)
        if not scan:
            return None
        return ScanRead.model_validate(scan)

    def list_scans_for_assessment(self, assessment_id: uuid.UUID) -> List[ScanRead]:
        """List all scan tool executions for an assessment."""
        scans = self.repository.list_by_assessment(assessment_id)
        return [ScanRead.model_validate(s) for s in scans]

    def get_scans_summary(self, assessment_id: uuid.UUID) -> Dict[str, Any]:
        """Return scan metrics, counts by tool and status, and recent history."""
        summary = self.repository.get_summary(assessment_id)
        summary["recent_scans"] = [ScanRead.model_validate(s) for s in summary["recent_scans"]]
        return summary
