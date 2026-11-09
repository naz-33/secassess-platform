import uuid
from typing import List, Optional, Dict, Any
from sqlalchemy import select, func, or_, case
from sqlalchemy.orm import Session, selectinload
from app.modules.findings.models import (
    Finding,
    Evidence,
    SeverityChange,
    FindingStatus,
    FindingSeverity,
    FindingSource,
)


class FindingRepository:
    """Repository handling database operations for findings, evidence, and severity changes."""

    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, finding_id: uuid.UUID) -> Optional[Finding]:
        return self.db.execute(
            select(Finding)
            .options(selectinload(Finding.evidences), selectinload(Finding.severity_changes))
            .where(Finding.id == finding_id)
        ).scalar_one_or_none()

    def get_by_fingerprint(self, assessment_id: uuid.UUID, fingerprint: str) -> Optional[Finding]:
        return self.db.execute(
            select(Finding)
            .options(selectinload(Finding.evidences), selectinload(Finding.severity_changes))
            .where(Finding.assessment_id == assessment_id, Finding.fingerprint == fingerprint)
        ).scalar_one_or_none()

    def create(self, finding: Finding) -> Finding:
        self.db.add(finding)
        self.db.commit()
        self.db.refresh(finding)
        return finding

    def update(self, finding: Finding) -> Finding:
        self.db.add(finding)
        self.db.commit()
        self.db.refresh(finding)
        return finding

    def list_findings(
        self,
        assessment_id: Optional[uuid.UUID] = None,
        category: Optional[str] = None,
        severity: Optional[FindingSeverity] = None,
        effective_severity: Optional[FindingSeverity] = None,
        status: Optional[FindingStatus] = None,
        source: Optional[FindingSource] = None,
        scan_id: Optional[uuid.UUID] = None,
        verified_by: Optional[uuid.UUID] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Finding]:
        query = (
            select(Finding)
            .options(selectinload(Finding.evidences), selectinload(Finding.severity_changes))
        )
        if assessment_id is not None:
            query = query.where(Finding.assessment_id == assessment_id)
        if category:
            query = query.where(Finding.category == category)
        if severity:
            query = query.where(Finding.severity == severity)
        if status:
            query = query.where(Finding.status == status)
        if source:
            query = query.where(Finding.source == source)
        if scan_id:
            query = query.where(Finding.scan_id == scan_id)
        if verified_by:
            query = query.where(Finding.verified_by == verified_by)
        if effective_severity:
            eff_col = func.coalesce(Finding.final_severity, Finding.original_severity, Finding.severity)
            query = query.where(eff_col == effective_severity)

        query = query.order_by(Finding.created_at.desc()).limit(limit).offset(offset)
        return list(self.db.execute(query).scalars().all())

    def list_by_assessment(
        self,
        assessment_id: uuid.UUID,
        category: Optional[str] = None,
        severity: Optional[FindingSeverity] = None,
        effective_severity: Optional[FindingSeverity] = None,
        status: Optional[FindingStatus] = None,
        source: Optional[FindingSource] = None,
        scan_id: Optional[uuid.UUID] = None,
        verified_by: Optional[uuid.UUID] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Finding]:
        return self.list_findings(
            assessment_id=assessment_id,
            category=category,
            severity=severity,
            effective_severity=effective_severity,
            status=status,
            source=source,
            scan_id=scan_id,
            verified_by=verified_by,
            limit=limit,
            offset=offset,
        )

    def get_summary(self, assessment_id: uuid.UUID) -> Dict[str, Any]:
        """Aggregate counts by severity, category, status, and confirmed effective severity."""
        findings = list(
            self.db.execute(
                select(
                    Finding.severity,
                    Finding.original_severity,
                    Finding.final_severity,
                    Finding.category,
                    Finding.status,
                )
                .where(Finding.assessment_id == assessment_id)
            ).all()
        )

        total = len(findings)
        by_severity = {s.value: 0 for s in FindingSeverity}
        by_status = {st.value: 0 for st in FindingStatus}
        confirmed_by_effective_severity = {s.value: 0 for s in FindingSeverity}
        by_category: Dict[str, int] = {}
        confirmed_by_category: Dict[str, int] = {}
        unverified_count = 0
        verified_count = 0

        for sev, orig_sev, fin_sev, cat, st in findings:
            eff = fin_sev if fin_sev is not None else (orig_sev or sev)
            eff_val = eff.value if hasattr(eff, "value") else str(eff)
            st_val = st.value if hasattr(st, "value") else str(st)
            cat_key = str(cat)

            by_severity[eff_val] = by_severity.get(eff_val, 0) + 1
            by_status[st_val] = by_status.get(st_val, 0) + 1
            by_category[cat_key] = by_category.get(cat_key, 0) + 1

            if st == FindingStatus.CONFIRMED:
                confirmed_by_effective_severity[eff_val] = (
                    confirmed_by_effective_severity.get(eff_val, 0) + 1
                )
                confirmed_by_category[cat_key] = (
                    confirmed_by_category.get(cat_key, 0) + 1
                )

            if st == FindingStatus.UNVERIFIED:
                unverified_count += 1
            else:
                verified_count += 1

        progress = round(verified_count / total, 4) if total > 0 else 0.0

        return {
            "total": total,
            "by_severity": by_severity,
            "by_category": by_category,
            "confirmed_by_category": confirmed_by_category,
            "by_status": by_status,
            "confirmed_by_effective_severity": confirmed_by_effective_severity,
            "unverified_count": unverified_count,
            "verified_count": verified_count,
            "verification_progress": progress,
        }

    def add_evidence(self, evidence: Evidence) -> Evidence:
        self.db.add(evidence)
        self.db.commit()
        self.db.refresh(evidence)
        return evidence

    def get_evidence_by_id(self, evidence_id: uuid.UUID) -> Optional[Evidence]:
        return self.db.execute(select(Evidence).where(Evidence.id == evidence_id)).scalar_one_or_none()

    def list_evidence_by_finding(self, finding_id: uuid.UUID) -> List[Evidence]:
        return list(
            self.db.execute(
                select(Evidence).where(Evidence.finding_id == finding_id).order_by(Evidence.captured_at.asc())
            ).scalars().all()
        )

    def add_severity_change(self, change: SeverityChange) -> SeverityChange:
        """Append-only addition of a severity change record."""
        self.db.add(change)
        self.db.commit()
        self.db.refresh(change)
        return change

    def list_severity_changes(self, finding_id: uuid.UUID) -> List[SeverityChange]:
        """List historical severity changes ordered chronologically."""
        return list(
            self.db.execute(
                select(SeverityChange)
                .where(SeverityChange.finding_id == finding_id)
                .order_by(SeverityChange.changed_at.asc())
            ).scalars().all()
        )

    def get_top_confirmed_findings(self, assessment_id: uuid.UUID, limit: int = 5) -> List[Finding]:
        """Retrieve highest effective-severity confirmed findings."""
        eff_col = func.coalesce(Finding.final_severity, Finding.original_severity, Finding.severity)
        severity_order = case(
            (eff_col == FindingSeverity.CRITICAL, 1),
            (eff_col == FindingSeverity.HIGH, 2),
            (eff_col == FindingSeverity.MEDIUM, 3),
            (eff_col == FindingSeverity.LOW, 4),
            (eff_col == FindingSeverity.INFO, 5),
            else_=6,
        )
        stmt = (
            select(Finding)
            .where(
                Finding.assessment_id == assessment_id,
                Finding.status == FindingStatus.CONFIRMED,
            )
            .order_by(severity_order.asc(), Finding.title.asc())
            .limit(limit)
        )
        return list(self.db.execute(stmt).scalars().all())

    def get_confirmed_findings_for_report(self, assessment_id: uuid.UUID) -> List[Finding]:
        """Retrieve all confirmed findings ordered by effective severity and title."""
        eff_col = func.coalesce(Finding.final_severity, Finding.original_severity, Finding.severity)
        severity_order = case(
            (eff_col == FindingSeverity.CRITICAL, 1),
            (eff_col == FindingSeverity.HIGH, 2),
            (eff_col == FindingSeverity.MEDIUM, 3),
            (eff_col == FindingSeverity.LOW, 4),
            (eff_col == FindingSeverity.INFO, 5),
            else_=6,
        )
        stmt = (
            select(Finding)
            .options(selectinload(Finding.evidences), selectinload(Finding.severity_changes))
            .where(
                Finding.assessment_id == assessment_id,
                Finding.status == FindingStatus.CONFIRMED,
            )
            .order_by(severity_order.asc(), Finding.title.asc())
        )
        return list(self.db.execute(stmt).scalars().all())

    def get_non_confirmed_findings_for_report(self, assessment_id: uuid.UUID) -> List[Finding]:
        """Retrieve all non-confirmed findings (unverified, false_positive, needs_testing)."""
        stmt = (
            select(Finding)
            .options(selectinload(Finding.evidences), selectinload(Finding.severity_changes))
            .where(
                Finding.assessment_id == assessment_id,
                Finding.status != FindingStatus.CONFIRMED,
            )
            .order_by(Finding.status.asc(), Finding.created_at.desc())
        )
        return list(self.db.execute(stmt).scalars().all())

