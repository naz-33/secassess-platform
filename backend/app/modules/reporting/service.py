"""Public service for security report generation, lifecycle, and downloads."""
import hashlib
import io
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from fastapi import BackgroundTasks, HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.exceptions import (
    NotFoundException,
    ForbiddenException,
    ConflictException,
    UnprocessableEntityException,
)
from app.modules.audit import AuditService
from app.modules.auth import User, AuthService
from app.modules.assessments import AssessmentService
from app.modules.targets import TargetService
from app.modules.findings import FindingService, FindingStatus, FindingSeverity
from app.modules.recon import ReconService
from app.modules.scans import ScanService
from app.modules.ai_analysis import AIAnalysisService
from app.modules.verification import VerificationService

from app.modules.reporting.models import Report, ReportFormat, ReportStatus
from app.modules.reporting.repository import ReportRepository
from app.modules.reporting.schemas import ReportGenerateRequest, ReportRead
from app.modules.reporting.generators.docx_generator import DocxReportGenerator
from app.modules.reporting.generators.pdf_generator import convert_docx_to_pdf, is_libreoffice_available

logger = logging.getLogger(__name__)


def _execute_report_background_worker(
    report_id: uuid.UUID,
    include_unverified_appendix: bool,
    title: Optional[str] = None,
    notes: Optional[str] = None,
) -> None:
    """Isolated background worker compiling assessment report and persisting document."""
    db = SessionLocal()
    try:
        service = ReportingService(db)
        service._run_report_pipeline(
            report_id=report_id,
            include_unverified_appendix=include_unverified_appendix,
            title=title,
            notes=notes,
        )
    except Exception as exc:
        logger.exception("Unexpected error in report background worker for %s: %s", report_id, exc)
    finally:
        db.close()


class ReportingService:
    """Public business logic service for generating vulnerability reports."""

    def __init__(self, db: Session):
        self.db = db
        self.repository = ReportRepository(db)
        self.audit_service = AuditService(db)
        self.assessment_service = AssessmentService(db)
        self.target_service = TargetService(db)
        self.finding_service = FindingService(db)
        self.recon_service = ReconService(db)
        self.scan_service = ScanService(db)
        self.ai_service = AIAnalysisService(db)
        self.verification_service = VerificationService(db)
        self.auth_service = AuthService(db)

    def request_report_generation(
        self,
        assessment_id: uuid.UUID,
        request: ReportGenerateRequest,
        user: User,
        background_tasks: Optional[BackgroundTasks] = None,
    ) -> ReportRead:
        """
        Initiate immutable report generation with strict role verification (Assessor/Admin).
        Enforces one generation at a time per assessment (409 on conflict).
        """
        user_role = user.role.value if hasattr(user.role, "value") else str(user.role)
        if user_role not in ("assessor", "admin"):
            raise ForbiddenException("Only assessors and administrators can generate reports.")

        assessment = self.assessment_service.get_assessment(assessment_id)
        if not assessment:
            raise NotFoundException("Assessment", assessment_id)

        # Enforce single generation at a time per assessment
        if self.repository.has_pending_report(assessment_id):
            raise ConflictException("A report generation task is already in progress for this assessment.")

        fmt_clean = request.format.strip().lower()
        if fmt_clean not in ("docx", "pdf"):
            raise UnprocessableEntityException(f"Unsupported report format '{request.format}'. Allowed: docx, pdf.")

        if fmt_clean == "pdf" and not is_libreoffice_available():
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="PDF conversion not available: LibreOffice is not installed or configured on the system.",
            )

        report_fmt = ReportFormat.PDF if fmt_clean == "pdf" else ReportFormat.DOCX
        version = self.repository.get_next_version(assessment_id)

        report = Report(
            assessment_id=assessment_id,
            version=version,
            format=report_fmt,
            status=ReportStatus.PENDING,
            generated_by=user.id,
            template_version="1.0.0",
            generator_version="1.0.0",
            snapshot_json={},
            unverified_count_at_generation=0,
            confirmed_count_at_generation=0,
        )
        created = self.repository.create(report)

        self.audit_service.log_action(
            action="report_generation_requested",
            detail={
                "report_id": str(created.id),
                "assessment_id": str(assessment_id),
                "format": created.format.value,
                "version": created.version,
            },
            user_id=user.id,
        )

        if background_tasks is not None:
            background_tasks.add_task(
                _execute_report_background_worker,
                created.id,
                request.include_unverified_appendix,
                request.title,
                request.notes,
            )
        else:
            self._run_report_pipeline(
                report_id=created.id,
                include_unverified_appendix=request.include_unverified_appendix,
                title=request.title,
                notes=request.notes,
            )
            refreshed = self.repository.get_by_id(created.id)
            return self._to_read_dto(refreshed or created)

        return self._to_read_dto(created)

    def _run_report_pipeline(
        self,
        report_id: uuid.UUID,
        include_unverified_appendix: bool,
        title: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> None:
        """Core execution routine gathering data, taking snapshot, rendering, and persisting."""
        report = self.repository.get_by_id(report_id)
        if not report or report.status != ReportStatus.PENDING:
            return

        try:
            assessment = self.assessment_service.get_assessment(report.assessment_id)
            if not assessment:
                raise NotFoundException("Assessment", report.assessment_id)

            target = self.target_service.get_target(assessment.target_id)
            scope_items = self.target_service.list_scope_items(assessment.target_id)
            confirmed_findings = self.finding_service.get_confirmed_findings_for_report(report.assessment_id)
            non_confirmed_findings = self.finding_service.get_non_confirmed_findings_for_report(report.assessment_id)
            summary = self.finding_service.get_findings_summary(report.assessment_id)
            assets = self.recon_service.list_assets(report.assessment_id)
            scans = self.scan_service.list_scans_for_assessment(report.assessment_id)
            approved_ai_summary = self.ai_service.get_approved_executive_summary(report.assessment_id)

            # Resolve reviewer name if AI summary exists
            if approved_ai_summary and approved_ai_summary.get("reviewed_by"):
                rev_user = self.auth_service.get_user_by_id(approved_ai_summary["reviewed_by"])
                approved_ai_summary["reviewed_by_name"] = rev_user.name if rev_user else "Assessor"

            # Resolve unique assessor names who verified findings
            assessor_ids = set()
            for f in confirmed_findings:
                if f.verified_by:
                    assessor_ids.add(f.verified_by)
            assessor_names = []
            for uid in assessor_ids:
                u = self.auth_service.get_user_by_id(uid)
                if u:
                    assessor_names.append(u.name)
            assessors_str = ", ".join(assessor_names) if assessor_names else "Security Assessment Team"

            # Collect verification trail and severity history
            verification_trail = []
            severity_history = []
            all_findings = confirmed_findings + non_confirmed_findings
            for f in all_findings:
                v_list = self.verification_service.list_verifications(f.id)
                for v in v_list:
                    u_obj = self.auth_service.get_user_by_id(v.assessor_id)
                    verification_trail.append({
                        "finding_id": f.id,
                        "assessor_name": u_obj.name if u_obj else "Assessor",
                        "decision": v.decision.value if hasattr(v.decision, "value") else str(v.decision),
                        "verified_at": v.verified_at,
                        "notes": v.notes,
                    })

                s_list = self.finding_service.list_severity_history(f.id)
                for s in s_list:
                    u_obj = self.auth_service.get_user_by_id(s.changed_by)
                    severity_history.append({
                        "finding_id": f.id,
                        "old_severity": s.old_severity.value if hasattr(s.old_severity, "value") else str(s.old_severity),
                        "new_severity": s.new_severity.value if hasattr(s.new_severity, "value") else str(s.new_severity),
                        "justification": s.justification,
                        "changed_by_name": u_obj.name if u_obj else "Assessor",
                        "changed_at": s.changed_at,
                    })

            # Exercised standards
            exercised_wstg = sorted(list({f.wstg_id for f in confirmed_findings if f.wstg_id}))
            exercised_owasp = sorted(list({f.owasp_top10 for f in confirmed_findings if f.owasp_top10}))
            exercised_cats = sorted(list({f.category for f in confirmed_findings if f.category}))

            # Evidence index and snapshot data
            evidence_index = []
            evidence_snapshot = []
            for f in all_findings:
                evs = self.finding_service.list_evidence_for_finding(f.id)
                for ev in evs:
                    evidence_index.append({
                        "id": ev.id,
                        "finding_id": f.id,
                        "type": ev.type.value if hasattr(ev.type, "value") else str(ev.type),
                        "label": ev.label,
                        "sha256": ev.sha256,
                        "captured_at": ev.captured_at,
                    })
                    evidence_snapshot.append({
                        "id": str(ev.id),
                        "sha256": ev.sha256,
                    })

            # Prepare findings dictionaries for docx generator
            def finding_to_dict(f) -> Dict[str, Any]:
                u_obj = self.auth_service.get_user_by_id(f.verified_by) if f.verified_by else None
                evs = self.finding_service.list_evidence_for_finding(f.id)
                return {
                    "id": f.id,
                    "title": f.title,
                    "category": f.category,
                    "description": f.description,
                    "effective_severity": f.effective_severity.value if hasattr(f.effective_severity, "value") else str(f.effective_severity),
                    "original_severity": f.original_severity.value if (f.original_severity and hasattr(f.original_severity, "value")) else str(f.original_severity or ""),
                    "severity_justification": f.severity_justification,
                    "cvss_score": f.cvss_score,
                    "cvss_vector": f.cvss_vector,
                    "wstg_id": f.wstg_id,
                    "owasp_top10": f.owasp_top10,
                    "cwe": f.cwe,
                    "affected_url": f.affected_url,
                    "status": f.status.value if hasattr(f.status, "value") else str(f.status),
                    "source": f.source.value if hasattr(f.source, "value") else str(f.source),
                    "remediation": f.remediation,
                    "verified_by_name": u_obj.name if u_obj else None,
                    "verified_at": f.verified_at,
                    "verification_notes": None,
                    "evidences": [
                        {
                            "id": e.id,
                            "type": e.type.value if hasattr(e.type, "value") else str(e.type),
                            "content": e.content,
                            "file_path": e.file_path,
                            "label": e.label,
                            "sha256": e.sha256,
                            "original_filename": e.original_filename,
                            "captured_at": e.captured_at,
                        }
                        for e in evs
                    ],
                }

            confirmed_dicts = [finding_to_dict(f) for f in confirmed_findings]
            non_confirmed_dicts = [finding_to_dict(f) for f in non_confirmed_findings]

            unverified_count = sum(1 for f in non_confirmed_findings if f.status == FindingStatus.UNVERIFIED)

            # Rule 5 Snapshot (JSON)
            snapshot = {
                "generator_version": "1.0.0",
                "template_version": "1.0.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "findings": [
                    {
                        "id": str(f.id),
                        "status": f.status.value if hasattr(f.status, "value") else str(f.status),
                        "effective_severity": f.effective_severity.value if hasattr(f.effective_severity, "value") else str(f.effective_severity),
                        "verified_at": f.verified_at.isoformat() if f.verified_at else None,
                    }
                    for f in all_findings
                ],
                "evidence": evidence_snapshot,
                "scans": [str(s.id) for s in scans],
                "ai_analysis_id_used": str(approved_ai_summary["id"]) if approved_ai_summary else None,
                "scope_items": [i.asset for i in scope_items],
            }

            compile_data = {
                "report_title": title or "SECURITY ASSESSMENT & VULNERABILITY REPORT",
                "target_name": target.name if target else "Assessment Target",
                "target_base_url": target.base_url if target else "",
                "target_authorization_note": target.authorization_note if target else "",
                "assessment_name": assessment.name,
                "version": report.version,
                "assessors": assessors_str,
                "unverified_count": unverified_count,
                "verified_count": summary.verified_count,
                "verification_progress": summary.verification_progress,
                "confirmed_by_severity": summary.confirmed_by_effective_severity,
                "confirmed_by_category": summary.confirmed_by_category,
                "approved_ai_summary": approved_ai_summary,
                "scope_items": [{"asset": s.asset, "in_scope": s.in_scope, "notes": s.notes} for s in scope_items],
                "exercised_wstg_ids": exercised_wstg,
                "exercised_owasp": exercised_owasp,
                "exercised_categories": exercised_cats,
                "confirmed_findings": confirmed_dicts,
                "non_confirmed_findings": non_confirmed_dicts if include_unverified_appendix else [],
                "assets": [
                    {"type": a.type.value if hasattr(a.type, "value") else str(a.type), "value": a.value, "details": a.details}
                    for a in assets
                ],
                "scans": [
                    {
                        "tool": s.tool.value if hasattr(s.tool, "value") else str(s.tool),
                        "command": s.command,
                        "started_at": s.started_at,
                        "finished_at": s.finished_at,
                        "status": s.status.value if hasattr(s.status, "value") else str(s.status),
                    }
                    for s in scans
                ],
                "verification_trail": verification_trail,
                "severity_history": severity_history,
                "evidence_index": evidence_index,
            }

            # Generate DOCX
            generator = DocxReportGenerator(compile_data)
            docx_buf = generator.generate()

            report_dir = Path(settings.REPORT_DIR)
            report_dir.mkdir(parents=True, exist_ok=True)

            unique_id = uuid.uuid4()
            docx_filename = f"report_{report.assessment_id}_v{report.version}_{unique_id.hex[:8]}.docx"
            docx_path = report_dir / docx_filename
            docx_path.write_bytes(docx_buf.getvalue())

            final_path = docx_path
            final_filename = docx_filename

            # If PDF requested, convert DOCX to PDF
            if report.format == ReportFormat.PDF:
                pdf_path_str = convert_docx_to_pdf(str(docx_path), str(report_dir))
                final_path = Path(pdf_path_str)
                final_filename = final_path.name

            file_bytes = final_path.read_bytes()
            sha256_hash = hashlib.sha256(file_bytes).hexdigest()
            size_bytes = len(file_bytes)

            # Update report status and metrics
            report.status = ReportStatus.COMPLETED
            report.file_path = str(final_path)
            report.filename = final_filename
            report.sha256 = sha256_hash
            report.size_bytes = size_bytes
            report.generated_at = datetime.now(timezone.utc)
            report.snapshot_json = snapshot
            report.unverified_count_at_generation = unverified_count
            report.confirmed_count_at_generation = len(confirmed_findings)
            report.error = None
            self.repository.update(report)

            self.audit_service.log_action(
                action="report_generated",
                detail={
                    "report_id": str(report.id),
                    "assessment_id": str(report.assessment_id),
                    "format": report.format.value,
                    "version": report.version,
                    "confirmed_count": len(confirmed_findings),
                    "unverified_count": unverified_count,
                    "sha256": sha256_hash,
                },
                user_id=report.generated_by,
            )

        except Exception as exc:
            logger.exception("Report generation pipeline failed for report %s: %s", report.id, exc)
            report.status = ReportStatus.FAILED
            report.error = str(exc)
            self.repository.update(report)

            self.audit_service.log_action(
                action="report_generation_failed",
                detail={
                    "report_id": str(report.id),
                    "assessment_id": str(report.assessment_id),
                    "error": str(exc),
                },
                user_id=report.generated_by,
            )

    def get_report(self, report_id: uuid.UUID) -> Optional[ReportRead]:
        """Fetch report metadata by ID."""
        report = self.repository.get_by_id(report_id)
        if not report:
            return None
        return self._to_read_dto(report)

    def list_reports(self, assessment_id: uuid.UUID) -> List[ReportRead]:
        """List reports generated for an assessment."""
        records = self.repository.list_by_assessment(assessment_id)
        return [self._to_read_dto(r) for r in records]

    def get_latest_report(self, assessment_id: uuid.UUID) -> Optional[ReportRead]:
        """Fetch the latest report generated for an assessment."""
        record = self.repository.get_latest_by_assessment(assessment_id)
        if not record:
            return None
        return self._to_read_dto(record)

    def get_report_download(self, report_id: uuid.UUID, user: User) -> Tuple[Path, str, str]:
        """
        Verify file integrity (SHA-256) and return path, media type, and attachment filename.
        Raises 500 error and logs audit trail if hash does not match disk contents.
        """
        report = self.repository.get_by_id(report_id)
        if not report:
            raise NotFoundException("Report", report_id)

        if report.status != ReportStatus.COMPLETED or not report.file_path:
            raise UnprocessableEntityException("Report is not ready for download or failed generation.")

        path = Path(report.file_path)
        if not path.exists():
            raise NotFoundException("Report file on disk", report_id)

        # Integrity verification
        actual_bytes = path.read_bytes()
        actual_hash = hashlib.sha256(actual_bytes).hexdigest()

        if report.sha256 and report.sha256 != actual_hash:
            self.audit_service.log_action(
                action="report_integrity_failed",
                detail={
                    "report_id": str(report_id),
                    "assessment_id": str(report.assessment_id),
                    "stored_sha256": report.sha256,
                    "computed_sha256": actual_hash,
                },
                user_id=user.id,
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Report integrity violation: File SHA-256 hash does not match the database record.",
            )

        self.audit_service.log_action(
            action="report_downloaded",
            detail={
                "report_id": str(report.id),
                "assessment_id": str(report.assessment_id),
                "format": report.format.value,
            },
            user_id=user.id,
        )

        media_type = (
            "application/pdf"
            if report.format == ReportFormat.PDF
            else "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        return path, media_type, report.filename or path.name

    def delete_report(self, report_id: uuid.UUID, user: User) -> bool:
        """Admin-only deletion of a generated report file and record."""
        user_role = user.role.value if hasattr(user.role, "value") else str(user.role)
        if user_role != "admin" and user.role != UserRole.ADMIN:
            raise ForbiddenException("Only administrators can delete reports.")

        report = self.repository.get_by_id(report_id)
        if not report:
            raise NotFoundException("Report", report_id)

        if report.file_path:
            p = Path(report.file_path)
            if p.exists():
                try:
                    p.unlink()
                except Exception as exc:
                    logger.warning("Could not unlink report file %s: %s", p, exc)

        self.repository.delete(report)

        self.audit_service.log_action(
            action="report_deleted",
            detail={
                "report_id": str(report_id),
                "assessment_id": str(report.assessment_id),
            },
            user_id=user.id,
        )
        return True

    def _to_read_dto(self, report: Report) -> ReportRead:
        return ReportRead(
            id=report.id,
            assessment_id=report.assessment_id,
            version=report.version,
            format=report.format.value if hasattr(report.format, "value") else str(report.format),
            status=report.status.value if hasattr(report.status, "value") else str(report.status),
            file_path=report.file_path,
            filename=report.filename,
            sha256=report.sha256,
            size_bytes=report.size_bytes,
            generated_by=report.generated_by,
            generated_at=report.generated_at,
            template_version=report.template_version,
            generator_version=report.generator_version,
            snapshot_json=report.snapshot_json or {},
            unverified_count_at_generation=report.unverified_count_at_generation,
            confirmed_count_at_generation=report.confirmed_count_at_generation,
            error=report.error,
            created_at=report.created_at,
        )
