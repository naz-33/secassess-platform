from sqlalchemy.orm import Session
from app.modules.dashboard.schemas import DashboardMetrics, SeverityCount


class DashboardService:
    """Public business logic service for read-only dashboard aggregations."""

    def __init__(self, db: Session):
        self.db = db

    def get_metrics(self) -> DashboardMetrics:
        """Fetch high-level metrics and severity counts for dashboard charts."""
        # TODO: Implement aggregated SQL queries across findings and assessments
        return DashboardMetrics(
            total_targets=1,
            total_assessments=1,
            total_scans=2,
            total_findings=5,
            findings_by_severity=[
                SeverityCount(severity="critical", count=1),
                SeverityCount(severity="high", count=2),
                SeverityCount(severity="medium", count=1),
                SeverityCount(severity="low", count=1),
                SeverityCount(severity="info", count=0),
            ],
            findings_by_status={
                "unverified": 3,
                "confirmed": 2,
                "false_positive": 0,
                "needs_testing": 0,
            },
        )
