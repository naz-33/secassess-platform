import uuid
from typing import List, Optional, Dict, Any
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from app.modules.scans.models import Scan, ScanStatus, ScanTool


class ScanRepository:
    """Repository handling database operations for scans."""

    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, scan_id: uuid.UUID) -> Optional[Scan]:
        return self.db.execute(select(Scan).where(Scan.id == scan_id)).scalar_one_or_none()

    def create(self, scan: Scan) -> Scan:
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def update(self, scan: Scan) -> Scan:
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def list_by_assessment(self, assessment_id: uuid.UUID) -> List[Scan]:
        return list(
            self.db.execute(
                select(Scan)
                .where(Scan.assessment_id == assessment_id)
                .order_by(Scan.created_at.desc())
            ).scalars().all()
        )

    def list_running_by_assessment(self, assessment_id: uuid.UUID) -> List[Scan]:
        return list(
            self.db.execute(
                select(Scan).where(
                    Scan.assessment_id == assessment_id,
                    Scan.status.in_([ScanStatus.RUNNING, ScanStatus.PENDING]),
                )
            ).scalars().all()
        )

    def count_active_scans(self) -> int:
        return self.db.execute(
            select(func.count(Scan.id)).where(Scan.status == ScanStatus.RUNNING)
        ).scalar() or 0

    def get_summary(self, assessment_id: uuid.UUID) -> Dict[str, Any]:
        """Aggregate counts by tool and status, get last scan time and recent history."""
        tool_counts_raw = dict(
            self.db.execute(
                select(Scan.tool, func.count(Scan.id))
                .where(Scan.assessment_id == assessment_id)
                .group_by(Scan.tool)
            ).all()
        )
        status_counts_raw = dict(
            self.db.execute(
                select(Scan.status, func.count(Scan.id))
                .where(Scan.assessment_id == assessment_id)
                .group_by(Scan.status)
            ).all()
        )
        by_tool = {t.value: tool_counts_raw.get(t, 0) for t in ScanTool}
        by_status = {s.value: status_counts_raw.get(s, 0) for s in ScanStatus}

        last_scan = self.db.execute(
            select(Scan.created_at)
            .where(Scan.assessment_id == assessment_id)
            .order_by(Scan.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()

        recent_scans = list(
            self.db.execute(
                select(Scan)
                .where(Scan.assessment_id == assessment_id)
                .order_by(Scan.created_at.desc())
                .limit(10)
            ).scalars().all()
        )

        return {
            "total": sum(by_status.values()),
            "by_tool": by_tool,
            "by_status": by_status,
            "last_scan_at": last_scan,
            "recent_scans": recent_scans,
        }

