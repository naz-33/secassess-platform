import csv
import hashlib
import io
import json
import os
import re
import uuid
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    NotFoundException,
    PayloadTooLargeException,
    UnsupportedMediaTypeException,
    UnprocessableEntityException,
    ForbiddenException,
)
from app.modules.audit import AuditService
from app.modules.assessments import AssessmentService
from app.modules.auth import User
from app.modules.findings.models import (
    Finding,
    Evidence,
    SeverityChange,
    FindingStatus,
    FindingSeverity,
    FindingSource,
    EvidenceType,
)
from app.modules.findings.repository import FindingRepository
from app.modules.findings.schemas import (
    FindingCreate,
    FindingRead,
    EvidenceCreate,
    EvidenceRead,
    NoteEvidenceCreate,
    SeverityUpdateRequest,
    SeverityChangeRead,
    FindingsSummary,
    compute_risk_rating,
)


def compute_finding_fingerprint(
    assessment_id: uuid.UUID,
    category: str,
    wstg_id: Optional[str],
    affected_url: Optional[str],
    title: str,
) -> str:
    """Deterministic hash used to de-duplicate findings across repeated scans."""
    raw = f"{assessment_id}:{category.lower().strip()}:{(wstg_id or '').strip()}:{(affected_url or '').strip()}:{title.strip()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def detect_and_validate_file_type(data: bytes, original_filename: str) -> Tuple[EvidenceType, str, str]:
    """
    Validate file content by magic bytes and reject dangerous formats.
    Allowed formats: PNG, JPEG, WEBP, PDF, TXT.
    Rejects: SVG, HTML, Executables (MZ, ELF, Mach-O).
    Returns: (EvidenceType, content_type, file_extension)
    """
    if not data:
        raise UnsupportedMediaTypeException("Uploaded file is empty.")

    # 1. Executables signatures
    if data.startswith(b"MZ") or data.startswith(b"\x7fELF") or data.startswith(b"\xca\xfe\xba\xbe") or data.startswith(b"\xfe\xed\xfa\xce"):
        raise UnsupportedMediaTypeException("Executable binaries and scripts are strictly prohibited.")

    # 2. Check for HTML / SVG / XML
    head = data[:2048].lower()
    if (
        b"<html" in head
        or b"<!doctype" in head
        or b"<svg" in head
        or b"<?xml" in head
        or b"<script" in head
        or b"<body" in head
    ):
        raise UnsupportedMediaTypeException("HTML, XML, and SVG formats are prohibited due to security risks.")

    # 3. Magic bytes inspection
    # PNG: \x89PNG\r\n\x1a\n
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return EvidenceType.SCREENSHOT, "image/png", ".png"

    # JPEG: \xff\xd8\xff
    if data.startswith(b"\xff\xd8\xff"):
        return EvidenceType.SCREENSHOT, "image/jpeg", ".jpg"

    # WEBP: RIFF....WEBP
    if len(data) >= 12 and data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return EvidenceType.SCREENSHOT, "image/webp", ".webp"

    # PDF: %PDF-
    if data.startswith(b"%PDF-"):
        return EvidenceType.OUTPUT, "application/pdf", ".pdf"

    # TXT: Check clean UTF-8 text without null bytes
    if b"\x00" not in data[:4096]:
        try:
            data.decode("utf-8")
            return EvidenceType.OUTPUT, "text/plain", ".txt"
        except UnicodeDecodeError:
            pass

    raise UnsupportedMediaTypeException(
        "Invalid or unsupported file format. Allowed types: PNG, JPEG, WEBP, PDF, TXT."
    )


def sanitize_filename(filename: str) -> str:
    """Sanitize client-supplied filename to prevent path traversal."""
    base = os.path.basename(filename)
    clean = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", base)
    return clean or "upload"


def sanitize_csv_cell(value: Any) -> str:
    """Neutralize spreadsheet formula injection by prepending single quote to active triggers."""
    if value is None:
        return ""
    val_str = str(value)
    if val_str and val_str[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{val_str}"
    return val_str


class FindingService:
    """Public business logic service for security vulnerability findings."""

    def __init__(self, db: Session):
        self.db = db
        self.repository = FindingRepository(db)
        self.audit_service = AuditService(db)
        self.assessment_service = AssessmentService(db)

    def create_finding(self, finding_in: FindingCreate) -> FindingRead:
        """
        Create a new finding record.
        Strict rule: A finding is ALWAYS created as 'unverified'.
        Only the Phase 4 verification workflow can set 'confirmed', 'false_positive', or 'needs_testing'.
        """
        if finding_in.status != FindingStatus.UNVERIFIED:
            raise ValueError(
                "Findings must always be created with status 'unverified'. "
                "Verification decisions are restricted exclusively to the verification workflow."
            )

        fingerprint = finding_in.fingerprint or compute_finding_fingerprint(
            assessment_id=finding_in.assessment_id,
            category=finding_in.category,
            wstg_id=finding_in.wstg_id,
            affected_url=finding_in.affected_url,
            title=finding_in.title,
        )

        existing = self.repository.get_by_fingerprint(
            assessment_id=finding_in.assessment_id,
            fingerprint=fingerprint,
        )
        if existing:
            # Re-running an assessment must NOT double the findings or reset verified status
            return self._to_read_dto(existing)

        finding = Finding(
            assessment_id=finding_in.assessment_id,
            scan_id=finding_in.scan_id,
            title=finding_in.title,
            category=finding_in.category,
            description=finding_in.description,
            severity=finding_in.severity,
            original_severity=finding_in.severity,
            final_severity=None,
            severity_justification=None,
            verified_by=None,
            verified_at=None,
            cvss_score=finding_in.cvss_score,
            cvss_vector=finding_in.cvss_vector,
            wstg_id=finding_in.wstg_id,
            owasp_top10=finding_in.owasp_top10,
            cwe=finding_in.cwe,
            affected_url=finding_in.affected_url,
            status=FindingStatus.UNVERIFIED,
            source=finding_in.source,
            ai_analysis_id=finding_in.ai_analysis_id,
            remediation=finding_in.remediation,
            fingerprint=fingerprint,
        )
        created = self.repository.create(finding)
        return self._to_read_dto(created)

    def ingest_candidate(
        self,
        assessment_id: uuid.UUID,
        title: str,
        category: str,
        description: str,
        severity: FindingSeverity,
        affected_url: str,
        scan_id: Optional[uuid.UUID] = None,
        cvss_score: Optional[float] = None,
        cvss_vector: Optional[str] = None,
        wstg_id: Optional[str] = None,
        owasp_top10: Optional[str] = None,
        cwe: Optional[str] = None,
        remediation: Optional[str] = None,
        evidence_content: Optional[str] = None,
        evidence_label: Optional[str] = None,
        evidence_type: EvidenceType = EvidenceType.REQUEST_RESPONSE,
    ) -> Finding:
        """
        Ingest a candidate finding with automatic deduplication.
        If a finding with the same fingerprint exists in this assessment,
        the new evidence is appended while PRESERVING any existing verification status.
        """
        fingerprint = compute_finding_fingerprint(
            assessment_id=assessment_id,
            category=category,
            wstg_id=wstg_id,
            affected_url=affected_url,
            title=title,
        )

        existing = self.repository.get_by_fingerprint(
            assessment_id=assessment_id,
            fingerprint=fingerprint,
        )

        if existing:
            # Preserve existing status and severity fields! Do not reset!
            target_finding = existing
        else:
            finding = Finding(
                assessment_id=assessment_id,
                scan_id=scan_id,
                title=title,
                category=category,
                description=description,
                severity=severity,
                original_severity=severity,
                final_severity=None,
                severity_justification=None,
                verified_by=None,
                verified_at=None,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                wstg_id=wstg_id,
                owasp_top10=owasp_top10,
                cwe=cwe,
                affected_url=affected_url,
                status=FindingStatus.UNVERIFIED,
                source=FindingSource.TOOL,
                remediation=remediation,
                fingerprint=fingerprint,
            )
            target_finding = self.repository.create(finding)

        if evidence_content:
            evidence = Evidence(
                finding_id=target_finding.id,
                scan_id=scan_id,
                type=evidence_type,
                content=evidence_content,
                label=evidence_label or f"Evidence for {title}",
            )
            self.repository.add_evidence(evidence)

        refreshed = self.repository.get_by_id(target_finding.id)
        return refreshed or target_finding

    def get_finding(self, finding_id: uuid.UUID) -> Optional[FindingRead]:
        """Fetch finding details with attached evidence and risk rating."""
        finding = self.repository.get_by_id(finding_id)
        if not finding:
            return None
        return self._to_read_dto(finding)

    def promote_ai_suggestion(
        self,
        assessment_id: uuid.UUID,
        ai_analysis_id: uuid.UUID,
        title: str,
        category: str,
        description: str,
        suggested_severity: FindingSeverity,
        scan_id: Optional[uuid.UUID] = None,
        wstg_id: Optional[str] = None,
        remediation: Optional[str] = None,
        affected_url: Optional[str] = None,
        evidence_ids: Optional[List[uuid.UUID]] = None,
    ) -> FindingRead:
        """
        Promote an AI-suggested candidate finding into an official finding.
        Strict invariant: Always created with source='ai' and status='unverified'.
        De-duplicated via Phase 3 fingerprint logic.
        Existing status or severity fields are NEVER altered.
        """
        fingerprint = compute_finding_fingerprint(
            assessment_id=assessment_id,
            category=category,
            wstg_id=wstg_id,
            affected_url=affected_url,
            title=title,
        )

        existing = self.repository.get_by_fingerprint(
            assessment_id=assessment_id,
            fingerprint=fingerprint,
        )

        if existing:
            # Retain existing verification status and severity; never modify them!
            target_finding = existing
            if not target_finding.ai_analysis_id:
                target_finding.ai_analysis_id = ai_analysis_id
                self.repository.update(target_finding)
        else:
            finding = Finding(
                assessment_id=assessment_id,
                scan_id=scan_id,
                title=title,
                category=category,
                description=description,
                severity=suggested_severity,
                original_severity=suggested_severity,
                final_severity=None,
                severity_justification=None,
                verified_by=None,
                verified_at=None,
                wstg_id=wstg_id,
                affected_url=affected_url,
                status=FindingStatus.UNVERIFIED,
                source=FindingSource.AI,
                ai_analysis_id=ai_analysis_id,
                remediation=remediation,
                fingerprint=fingerprint,
            )
            target_finding = self.repository.create(finding)

        # Link cited evidence if provided
        if evidence_ids:
            for eid in evidence_ids:
                ev = self.repository.get_evidence_by_id(eid)
                if ev and ev.finding_id != target_finding.id:
                    new_ev = Evidence(
                        finding_id=target_finding.id,
                        scan_id=ev.scan_id or scan_id,
                        type=ev.type,
                        content=ev.content,
                        file_path=ev.file_path,
                        label=f"AI cited evidence ({ev.label or 'artifact'})",
                        uploaded_by=ev.uploaded_by,
                        sha256=ev.sha256,
                        original_filename=ev.original_filename,
                    )
                    self.repository.add_evidence(new_ev)

        refreshed = self.repository.get_by_id(target_finding.id)
        return self._to_read_dto(refreshed or target_finding)

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
    ) -> List[FindingRead]:
        """List findings across all assessments or for a specific assessment with optional filtering."""
        findings = self.repository.list_findings(
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

        # Batch lookup assessment names to populate assessment_name
        unique_assessment_ids = {f.assessment_id for f in findings}
        assessment_name_map: Dict[uuid.UUID, str] = {}
        for aid in unique_assessment_ids:
            a = self.assessment_service.get_assessment(aid)
            if a:
                assessment_name_map[aid] = a.name

        return [self._to_read_dto(f, assessment_name=assessment_name_map.get(f.assessment_id)) for f in findings]

    def get_findings_summary(self, assessment_id: uuid.UUID) -> FindingsSummary:
        """Return counts by severity, category, status, and confirmed effective severity."""
        data = self.repository.get_summary(assessment_id)
        return FindingsSummary(**data)

    def apply_verified_status(
        self,
        finding_id: uuid.UUID,
        decision: FindingStatus,
        assessor_id: uuid.UUID,
        verified_at: Any,
    ) -> Tuple[FindingRead, str]:
        """
        Sanctioned internal updater called exclusively by the VerificationService.
        Updates finding status, verified_by, and verified_at.
        Returns: (updated_finding, previous_status_str)
        """
        finding = self.repository.get_by_id(finding_id)
        if not finding:
            raise NotFoundException("Finding", finding_id)

        previous_status = finding.status.value if hasattr(finding.status, "value") else str(finding.status)
        finding.status = decision
        finding.verified_by = assessor_id
        finding.verified_at = verified_at
        self.repository.update(finding)

        refreshed = self.repository.get_by_id(finding_id)
        return self._to_read_dto(refreshed or finding), previous_status

    def override_severity(
        self,
        finding_id: uuid.UUID,
        override_in: SeverityUpdateRequest,
        user: User,
    ) -> FindingRead:
        """
        Assessor severity rating override with mandatory justification and append-only audit trail.
        """
        if user.role.value not in ("assessor", "admin") and user.role not in ("assessor", "admin"):
            raise ForbiddenException("Only assessors and administrators can override finding severity.")

        if len(override_in.justification.strip()) < settings.MIN_JUSTIFICATION_LENGTH:
            raise UnprocessableEntityException(
                f"Justification must be at least {settings.MIN_JUSTIFICATION_LENGTH} characters."
            )

        finding = self.repository.get_by_id(finding_id)
        if not finding:
            raise NotFoundException("Finding", finding_id)

        old_severity = finding.effective_severity
        new_severity = override_in.severity
        old_cvss = finding.cvss_score
        new_cvss = override_in.cvss_score

        # Record immutable severity change row
        change = SeverityChange(
            finding_id=finding.id,
            old_severity=old_severity,
            new_severity=new_severity,
            old_cvss=old_cvss,
            new_cvss=new_cvss,
            justification=override_in.justification.strip(),
            changed_by=user.id,
        )
        self.repository.add_severity_change(change)

        # Update finding fields (original_severity stays untouched!)
        finding.final_severity = new_severity
        finding.severity_justification = override_in.justification.strip()
        if override_in.cvss_score is not None:
            finding.cvss_score = override_in.cvss_score
        if override_in.cvss_vector is not None:
            finding.cvss_vector = override_in.cvss_vector

        self.repository.update(finding)

        # Audit log
        self.audit_service.log_action(
            action="severity_overridden",
            detail={
                "finding_id": str(finding.id),
                "old_severity": old_severity.value if hasattr(old_severity, "value") else str(old_severity),
                "new_severity": new_severity.value if hasattr(new_severity, "value") else str(new_severity),
                "old_cvss": old_cvss,
                "new_cvss": new_cvss,
                "justification": override_in.justification.strip(),
            },
            user_id=user.id,
        )

        refreshed = self.repository.get_by_id(finding.id)
        return self._to_read_dto(refreshed or finding)

    def list_severity_history(self, finding_id: uuid.UUID) -> List[SeverityChangeRead]:
        """Fetch chronological history of severity modifications for a finding."""
        finding = self.repository.get_by_id(finding_id)
        if not finding:
            raise NotFoundException("Finding", finding_id)
        changes = self.repository.list_severity_changes(finding_id)
        return [SeverityChangeRead.model_validate(c) for c in changes]

    def upload_evidence(
        self,
        finding_id: uuid.UUID,
        file_bytes: bytes,
        original_filename: str,
        label: Optional[str],
        notes: Optional[str],
        user: User,
    ) -> EvidenceRead:
        """
        Store manual evidence file with magic bytes validation, SHA-256 computation,
        and secure disk persistence outside the web root.
        """
        if user.role.value not in ("assessor", "admin") and user.role not in ("assessor", "admin"):
            raise ForbiddenException("Only assessors and administrators can upload evidence.")

        finding = self.repository.get_by_id(finding_id)
        if not finding:
            raise NotFoundException("Finding", finding_id)

        # Check maximum file size
        if len(file_bytes) > settings.MAX_UPLOAD_BYTES:
            raise PayloadTooLargeException(
                f"File size exceeds maximum permitted limit ({settings.MAX_UPLOAD_BYTES} bytes)."
            )

        # Validate magic bytes
        evidence_type, content_type, ext = detect_and_validate_file_type(file_bytes, original_filename)

        # Ensure upload directory exists
        upload_dir = Path(settings.UPLOAD_DIR).resolve()
        upload_dir.mkdir(parents=True, exist_ok=True)

        # Generate unique storage filename
        stored_file_id = uuid.uuid4()
        storage_filename = f"{stored_file_id}{ext}"
        storage_path = upload_dir / storage_filename

        # Write to disk safely
        with open(storage_path, "wb") as f:
            f.write(file_bytes)

        # Compute SHA-256
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()
        sanitized_name = sanitize_filename(original_filename)

        evidence = Evidence(
            finding_id=finding.id,
            type=evidence_type,
            content=notes,
            file_path=str(storage_path),
            label=label or f"Manual Evidence: {sanitized_name}",
            uploaded_by=user.id,
            sha256=sha256_hash,
            original_filename=sanitized_name,
        )
        created = self.repository.add_evidence(evidence)

        # Audit log
        self.audit_service.log_action(
            action="evidence_uploaded",
            detail={
                "finding_id": str(finding.id),
                "evidence_id": str(created.id),
                "original_filename": sanitized_name,
                "sha256": sha256_hash,
                "size_bytes": len(file_bytes),
            },
            user_id=user.id,
        )

        return EvidenceRead.model_validate(created)

    def add_note_evidence(
        self,
        finding_id: uuid.UUID,
        note_in: NoteEvidenceCreate,
        user: User,
    ) -> EvidenceRead:
        """Attach assessor text notes as an evidence entry."""
        if user.role.value not in ("assessor", "admin") and user.role not in ("assessor", "admin"):
            raise ForbiddenException("Only assessors and administrators can add evidence notes.")

        finding = self.repository.get_by_id(finding_id)
        if not finding:
            raise NotFoundException("Finding", finding_id)

        evidence = Evidence(
            finding_id=finding.id,
            type=EvidenceType.OUTPUT,
            content=note_in.notes.strip(),
            file_path=None,
            label=note_in.label or "Assessor Note",
            uploaded_by=user.id,
        )
        created = self.repository.add_evidence(evidence)

        self.audit_service.log_action(
            action="evidence_uploaded",
            detail={
                "finding_id": str(finding.id),
                "evidence_id": str(created.id),
                "type": "note",
            },
            user_id=user.id,
        )

        return EvidenceRead.model_validate(created)

    def get_evidence_download(
        self,
        evidence_id: uuid.UUID,
        user: User,
    ) -> Tuple[Path, str, str]:
        """
        Validate and prepare evidence file for secure attachment download.
        Returns: (file_path, content_type, filename)
        """
        evidence = self.repository.get_evidence_by_id(evidence_id)
        if not evidence or not evidence.file_path:
            raise NotFoundException("Evidence file", evidence_id)

        path = Path(evidence.file_path).resolve()
        if not path.exists() or not path.is_file():
            raise NotFoundException("Evidence file on disk", evidence_id)

        # Prevent path traversal outside UPLOAD_DIR
        upload_dir = Path(settings.UPLOAD_DIR).resolve()
        try:
            path.relative_to(upload_dir)
        except ValueError:
            raise ForbiddenException("Invalid evidence file path access.")

        # Determine content type
        ext = path.suffix.lower()
        content_type = "application/octet-stream"
        if ext == ".png":
            content_type = "image/png"
        elif ext in (".jpg", ".jpeg"):
            content_type = "image/jpeg"
        elif ext == ".webp":
            content_type = "image/webp"
        elif ext == ".pdf":
            content_type = "application/pdf"
        elif ext == ".txt":
            content_type = "text/plain"

        filename = evidence.original_filename or f"evidence_{evidence.id}{ext}"

        self.audit_service.log_action(
            action="evidence_downloaded",
            detail={
                "evidence_id": str(evidence.id),
                "finding_id": str(evidence.finding_id),
                "filename": filename,
            },
            user_id=user.id,
        )

        return path, content_type, filename

    def attach_evidence(
        self,
        finding_id: uuid.UUID,
        evidence_in: EvidenceCreate,
    ) -> EvidenceRead:
        """Internal/tool attach evidence."""
        finding = self.repository.get_by_id(finding_id)
        if not finding:
            raise NotFoundException("Finding", finding_id)

        evidence = Evidence(
            finding_id=finding_id,
            scan_id=evidence_in.scan_id,
            type=evidence_in.type,
            content=evidence_in.content,
            file_path=evidence_in.file_path,
            label=evidence_in.label,
            uploaded_by=evidence_in.uploaded_by,
            sha256=evidence_in.sha256,
            original_filename=evidence_in.original_filename,
        )
        created = self.repository.add_evidence(evidence)
        return EvidenceRead.model_validate(created)

    def get_evidence(self, evidence_id: uuid.UUID) -> Optional[EvidenceRead]:
        evidence = self.repository.get_evidence_by_id(evidence_id)
        if not evidence:
            return None
        return EvidenceRead.model_validate(evidence)

    def list_evidence_for_finding(self, finding_id: uuid.UUID) -> List[EvidenceRead]:
        evidences = self.repository.list_evidence_by_finding(finding_id)
        return [EvidenceRead.model_validate(e) for e in evidences]

    def _to_read_dto(self, finding: Finding, assessment_name: Optional[str] = None) -> FindingRead:
        eff = finding.effective_severity
        eff_sev = eff.value if hasattr(eff, "value") else str(eff)
        risk = compute_risk_rating(eff)

        data = {
            "id": finding.id,
            "assessment_id": finding.assessment_id,
            "scan_id": finding.scan_id,
            "title": finding.title,
            "category": finding.category,
            "description": finding.description,
            "severity": finding.severity,
            "original_severity": finding.original_severity or finding.severity,
            "final_severity": finding.final_severity,
            "effective_severity": eff,
            "severity_justification": finding.severity_justification,
            "verified_by": finding.verified_by,
            "verified_at": finding.verified_at,
            "risk_rating": risk,
            "assessment_name": assessment_name,
            "cvss_score": finding.cvss_score,
            "cvss_vector": finding.cvss_vector,
            "wstg_id": finding.wstg_id,
            "owasp_top10": finding.owasp_top10,
            "cwe": finding.cwe,
            "affected_url": finding.affected_url,
            "status": finding.status,
            "source": finding.source,
            "ai_analysis_id": finding.ai_analysis_id,
            "remediation": finding.remediation,
            "fingerprint": finding.fingerprint,
            "created_at": finding.created_at,
            "updated_at": finding.updated_at,
            "evidences": [EvidenceRead.model_validate(e) for e in (finding.evidences or [])],
        }
        return FindingRead(**data)

    def get_top_findings(self, assessment_id: uuid.UUID, limit: int = 5) -> List[FindingRead]:
        """Fetch top confirmed findings ordered by highest effective severity."""
        findings = self.repository.get_top_confirmed_findings(assessment_id, limit=limit)
        return [self._to_read_dto(f) for f in findings]

    def get_confirmed_findings_for_report(self, assessment_id: uuid.UUID) -> List[Finding]:
        """Fetch confirmed findings with relations for reporting."""
        return self.repository.get_confirmed_findings_for_report(assessment_id)

    def get_non_confirmed_findings_for_report(self, assessment_id: uuid.UUID) -> List[Finding]:
        """Fetch unverified, false positive, and needs-testing findings with relations for reporting."""
        return self.repository.get_non_confirmed_findings_for_report(assessment_id)

    def prepare_findings_export(
        self,
        assessment_id: uuid.UUID,
        format_type: str,
        status_filter: str,
        user: User,
    ) -> Tuple[Any, str, str]:
        """
        Prepare streamed export of findings with strict CSV formula injection neutralization
        and immutable audit logging. Returns (content_generator, media_type, filename).
        """
        user_role = user.role.value if hasattr(user.role, "value") else str(user.role)
        if user_role not in ("assessor", "admin"):
            raise ForbiddenException("Only assessors and administrators can export findings.")

        fmt = format_type.strip().lower()
        if fmt not in ("csv", "json"):
            raise UnprocessableEntityException(f"Unsupported export format '{format_type}'. Must be 'csv' or 'json'.")

        status_clean = (status_filter or "confirmed").strip().lower()
        filter_status = None
        if status_clean != "all":
            try:
                filter_status = FindingStatus(status_clean)
            except ValueError:
                raise UnprocessableEntityException(
                    f"Invalid status filter '{status_filter}'. Allowed: confirmed, unverified, false_positive, needs_testing, all."
                )

        findings = self.repository.list_by_assessment(
            assessment_id=assessment_id,
            status=filter_status,
            limit=5000,
        )

        rows = []
        for f in findings:
            eff_sev = f.effective_severity
            orig_sev = f.original_severity or f.severity
            is_confirmed = (f.status == FindingStatus.CONFIRMED or getattr(f.status, "value", str(f.status)) == "confirmed")
            row = {
                "id": str(f.id),
                "title": f.title,
                "category": f.category,
                "effective_severity": eff_sev.value if hasattr(eff_sev, "value") else str(eff_sev),
                "original_severity": orig_sev.value if hasattr(orig_sev, "value") else str(orig_sev),
                "status": f.status.value if hasattr(f.status, "value") else str(f.status),
                "verified": is_confirmed,
                "source": f.source.value if hasattr(f.source, "value") else str(f.source),
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector or "",
                "wstg_id": f.wstg_id or "",
                "owasp_top10": f.owasp_top10 or "",
                "cwe": f.cwe or "",
                "affected_url": f.affected_url or "",
                "remediation": f.remediation or "",
                "verified_by": str(f.verified_by) if f.verified_by else "",
                "verified_at": f.verified_at.isoformat() if f.verified_at else "",
            }
            rows.append(row)

        self.audit_service.log_action(
            action="findings_exported",
            detail={
                "assessment_id": str(assessment_id),
                "format": fmt,
                "status_filter": status_clean,
                "row_count": len(rows),
            },
            user_id=user.id,
        )

        headers_order = [
            "id", "title", "category", "effective_severity", "original_severity",
            "status", "verified", "source", "cvss_score", "cvss_vector",
            "wstg_id", "owasp_top10", "cwe", "affected_url", "remediation",
            "verified_by", "verified_at"
        ]

        if fmt == "csv":
            def csv_generator():
                output = io.StringIO()
                writer = csv.writer(output, lineterminator="\n")
                writer.writerow(headers_order)
                yield output.getvalue()
                output.seek(0)
                output.truncate(0)

                for r in rows:
                    sanitized_row = [sanitize_csv_cell(r.get(h, "")) for h in headers_order]
                    writer.writerow(sanitized_row)
                    yield output.getvalue()
                    output.seek(0)
                    output.truncate(0)

            return csv_generator(), "text/csv; charset=utf-8", f"findings_{assessment_id}.csv"

        else:
            def json_generator():
                yield "[\n"
                for idx, r in enumerate(rows):
                    line = json.dumps(r, indent=2)
                    if idx < len(rows) - 1:
                        line += ",\n"
                    else:
                        line += "\n"
                    yield line
                yield "]\n"

            return json_generator(), "application/json; charset=utf-8", f"findings_{assessment_id}.json"

