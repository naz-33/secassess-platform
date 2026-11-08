from typing import Dict, List
from pydantic import BaseModel


class SeverityCount(BaseModel):
    severity: str
    count: int


class DashboardMetrics(BaseModel):
    total_targets: int = 0
    total_assessments: int = 0
    total_scans: int = 0
    total_findings: int = 0
    findings_by_severity: List[SeverityCount] = []
    findings_by_status: Dict[str, int] = {}
