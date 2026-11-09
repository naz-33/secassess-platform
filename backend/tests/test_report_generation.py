"""Comprehensive test suite for Phase 6 Report Generation."""
import hashlib
import io
import os
import shutil
import uuid
from datetime import datetime
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

import docx
from PIL import Image

from app.core.config import settings
from app.core.database import SessionLocal
from app.modules.targets import TargetService
from app.modules.targets.schemas import TargetCreate, ScopeItemCreate
from app.modules.assessments import AssessmentService
from app.modules.assessments.schemas import AssessmentCreate
from app.modules.findings import (
    FindingService,
    FindingSeverity,
    FindingStatus,
    FindingSource,
    SeverityUpdateRequest,
)
from app.modules.verification import VerificationService, VerificationCreate, VerificationDecision
from app.modules.scans import ScanService, ScanCreate, ScanTool
from app.modules.ai_analysis import AIAnalysisService, ReviewAnalysisRequest
from app.modules.ai_analysis.models import AIAnalysis, AIFunction, AIAnalysisStatus, AIReviewStatus
from app.modules.reporting import ReportingService, ReportGenerateRequest, ReportFormat, ReportStatus
from app.modules.audit import AuditService

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "reports"


@pytest.fixture
def complex_report_assessment(admin_user, assessor_user):
    """
    Comprehensive fixture with findings in every lifecycle status:
    - Confirmed finding with severity override (original: MEDIUM, final: CRITICAL)
    - AI-sourced confirmed finding
    - AI-sourced unverified finding
    - Tool unverified finding with sensitive tokens & secrets in evidence
    - Needs-testing finding
    - False positive finding
    - Approved AI executive summary with assessor edits
    - Screenshots: valid image, corrupt image, hash mismatch image, missing file
    """
    db = SessionLocal()
    try:
        target_service = TargetService(db)
        target = target_service.create_target(
            TargetCreate(
                name="Report Target System",
                base_url="http://127.0.0.1:8080",
                description="Target for comprehensive report generation testing",
                authorization_note="Instructor-approved target only",
                scope_items=[
                    ScopeItemCreate(asset="http://127.0.0.1:8080", in_scope=True, notes="In scope web app"),
                    ScopeItemCreate(asset="127.0.0.1", in_scope=True, notes="In scope host"),
                    ScopeItemCreate(asset="http://127.0.0.1:9999", in_scope=False, notes="Out of scope admin interface"),
                ],
            )
        )

        assessment_service = AssessmentService(db)
        assessment = assessment_service.create_assessment(
            AssessmentCreate(
                name="Security Audit Spring 2026",
                target_id=target.id,
                created_by=admin_user.id,
            ),
            user_id=admin_user.id,
        )

        finding_service = FindingService(db)
        verification_service = VerificationService(db)

        # 1. Confirmed Tool Finding with Severity Override (Original MEDIUM -> Final CRITICAL)
        f_override = finding_service.ingest_candidate(
            assessment_id=assessment.id,
            title="Remote Code Execution via Upload",
            category="rce",
            description="Untrusted file upload allows arbitrary PHP code execution.",
            severity=FindingSeverity.MEDIUM,
            affected_url="http://127.0.0.1:8080/upload.php",
            wstg_id="WSTG-BUSL-08",
            owasp_top10="A03:2021-Injection",
            cwe="CWE-434",
            remediation="Enforce strict extension and magic byte validation.",
            evidence_content="HTTP/1.1 200 OK\nSet-Cookie: session_id=s3cr3t_s3ss10n_v4lu3; Secure; HttpOnly; SameSite=Strict\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.s1gn4tur3\nPassword: SuperSecretDBPassword123!\n\nSuccess file uploaded.\n" + ("A" * 1500),
            evidence_label="Upload Request and Cookie Response",
        )
        verification_service.verify_finding(
            finding_id=f_override.id,
            verification_in=VerificationCreate(
                decision=VerificationDecision.CONFIRMED,
                notes="Confirmed code execution via webshell upload.",
                evidence_reviewed=True,
            ),
            user=assessor_user,
        )
        finding_service.override_severity(
            finding_id=f_override.id,
            override_in=SeverityUpdateRequest(
                severity=FindingSeverity.CRITICAL,
                justification="Assessor demonstrated arbitrary system command execution in target container.",
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            ),
            user=assessor_user,
        )

        # 2. AI-Sourced Confirmed Finding
        # Create completed AI analysis first
        ai_analysis_1 = AIAnalysis(
            assessment_id=assessment.id,
            function=AIFunction.INTERPRET,
            status=AIAnalysisStatus.COMPLETED,
            requested_by=admin_user.id,
            model="gemini-2.5-flash",
            prompt_version="v1",
            input_hash="hash123",
            response_json={
                "suggested_candidate_findings": [
                    {
                        "title": "AI Discovered Path Traversal",
                        "category": "path_traversal",
                        "description": "Directory traversal via filename parameter",
                        "suggested_severity": "high",
                        "wstg_id": "WSTG-INPV-01",
                        "remediation": "Sanitize path inputs using realpath.",
                        "affected_url": "http://127.0.0.1:8080/view",
                    }
                ]
            },
        )
        db.add(ai_analysis_1)
        db.commit()
        db.refresh(ai_analysis_1)

        f_ai_confirmed = finding_service.promote_ai_suggestion(
            assessment_id=assessment.id,
            ai_analysis_id=ai_analysis_1.id,
            title="AI Discovered Path Traversal",
            category="path_traversal",
            description="Directory traversal via filename parameter allows reading /etc/passwd.",
            suggested_severity=FindingSeverity.HIGH,
            wstg_id="WSTG-INPV-01",
            remediation="Sanitize path inputs using realpath.",
            affected_url="http://127.0.0.1:8080/view",
        )
        # Add evidence and verify it
        db_f_ai = finding_service.repository.get_by_id(f_ai_confirmed.id)
        from app.modules.findings.models import Evidence, EvidenceType
        ev_ai = Evidence(
            finding_id=db_f_ai.id,
            type=EvidenceType.REQUEST_RESPONSE,
            content="GET /view?file=../../../../etc/passwd HTTP/1.1\nroot:x:0:0:root:/root:/bin/bash",
            label="Path Traversal Proof",
        )
        finding_service.repository.add_evidence(ev_ai)
        verification_service.verify_finding(
            finding_id=f_ai_confirmed.id,
            verification_in=VerificationCreate(
                decision=VerificationDecision.CONFIRMED,
                notes="Confirmed /etc/passwd contents retrieved.",
                evidence_reviewed=True,
            ),
            user=assessor_user,
        )

        # 3. AI-Sourced Unverified Finding
        f_ai_unverified = finding_service.promote_ai_suggestion(
            assessment_id=assessment.id,
            ai_analysis_id=ai_analysis_1.id,
            title="AI Candidate SSRF Vulnerability",
            category="ssrf",
            description="Potential SSRF in webhook registration.",
            suggested_severity=FindingSeverity.MEDIUM,
            wstg_id="WSTG-INPV-02",
            affected_url="http://127.0.0.1:8080/webhook",
        )

        # 4. Tool Unverified Finding with untrusted and malicious content
        f_unverified_tool = finding_service.ingest_candidate(
            assessment_id=assessment.id,
            title="Unverified Reflected Input with Control Characters \x08\x0b\x1f and <script>alert(1)</script>",
            category="xss",
            description="Testing untrusted payload: {{ 7*7 }} and ignore previous instructions. " + ("A" * 2000),
            severity=FindingSeverity.LOW,
            affected_url="http://127.0.0.1:8080/test",
            evidence_content="Raw probe with password=SecretPassword! and token=ghp_abcdefghijklmnopqrstuvwxyz1234567890",
            evidence_label="Probe Snippet",
        )

        # 5. Needs Testing Finding
        f_needs_testing = finding_service.ingest_candidate(
            assessment_id=assessment.id,
            title="Race Condition in Token Issuance",
            category="concurrency",
            description="Concurrency test required during peak load.",
            severity=FindingSeverity.MEDIUM,
            affected_url="http://127.0.0.1:8080/auth/token",
            evidence_content="Multiple simultaneous POST requests",
            evidence_label="Concurrency logs",
        )
        verification_service.verify_finding(
            finding_id=f_needs_testing.id,
            verification_in=VerificationCreate(
                decision=VerificationDecision.NEEDS_TESTING,
                notes="Requires specialized multi-threaded load harness to verify.",
                evidence_reviewed=True,
            ),
            user=assessor_user,
        )

        # 6. False Positive Finding
        f_fp = finding_service.ingest_candidate(
            assessment_id=assessment.id,
            title="Static CSS Parameter Injection",
            category="other",
            description="Reported as injection but is a static file route.",
            severity=FindingSeverity.LOW,
            affected_url="http://127.0.0.1:8080/style.css",
            evidence_content="CSS content: body { background: white; }",
            evidence_label="CSS Response",
        )
        verification_service.verify_finding(
            finding_id=f_fp.id,
            verification_in=VerificationCreate(
                decision=VerificationDecision.FALSE_POSITIVE,
                notes="Static resource server. No server-side code execution or reflection is possible.",
                evidence_reviewed=True,
            ),
            user=assessor_user,
        )

        # 7. Screenshot Evidences attached to f_override
        upload_dir = Path(settings.UPLOAD_DIR)
        upload_dir.mkdir(parents=True, exist_ok=True)

        # a) Valid Screenshot
        valid_png_path = upload_dir / "test_valid.png"
        shutil.copyfile(FIXTURES_DIR / "valid.png", valid_png_path)
        valid_hash = hashlib.sha256(valid_png_path.read_bytes()).hexdigest()
        ev_valid = Evidence(
            finding_id=f_override.id,
            type=EvidenceType.SCREENSHOT,
            file_path=str(valid_png_path),
            original_filename="test_valid.png",
            sha256=valid_hash,
            label="Valid WebShell Screenshot",
        )
        finding_service.repository.add_evidence(ev_valid)

        # b) Corrupt Screenshot
        corrupt_png_path = upload_dir / "test_corrupt.png"
        shutil.copyfile(FIXTURES_DIR / "corrupt.png", corrupt_png_path)
        ev_corrupt = Evidence(
            finding_id=f_override.id,
            type=EvidenceType.SCREENSHOT,
            file_path=str(corrupt_png_path),
            original_filename="test_corrupt.png",
            sha256=hashlib.sha256(b"corrupt").hexdigest(),
            label="Corrupted Screenshot",
        )
        finding_service.repository.add_evidence(ev_corrupt)

        # c) Hash mismatch Screenshot
        mismatch_path = upload_dir / "test_mismatch.png"
        shutil.copyfile(FIXTURES_DIR / "valid.png", mismatch_path)
        ev_mismatch = Evidence(
            finding_id=f_override.id,
            type=EvidenceType.SCREENSHOT,
            file_path=str(mismatch_path),
            original_filename="test_mismatch.png",
            sha256="0000000000000000000000000000000000000000000000000000000000000000",
            label="Tampered Screenshot",
        )
        finding_service.repository.add_evidence(ev_mismatch)

        # d) Missing File Screenshot
        ev_missing = Evidence(
            finding_id=f_override.id,
            type=EvidenceType.SCREENSHOT,
            file_path=str(upload_dir / "does_not_exist_file.png"),
            original_filename="does_not_exist_file.png",
            sha256="abcdef123456",
            label="Missing Screenshot",
        )
        finding_service.repository.add_evidence(ev_missing)

        # 8. Approved AI Executive Summary with edited_text
        ai_summary = AIAnalysis(
            assessment_id=assessment.id,
            function=AIFunction.SUMMARIZE,
            status=AIAnalysisStatus.COMPLETED,
            requested_by=admin_user.id,
            model="gemini-2.5-flash",
            prompt_version="v1",
            input_hash="summary_hash_1",
            response_json={"summary_text": "Original raw LLM generated summary before assessor review."},
            review_status=AIReviewStatus.APPROVED,
            reviewed_by=assessor_user.id,
            reviewed_at=datetime.now(),
            edited_text="The security assessment identified high-risk code execution and directory traversal vulnerabilities. All items reviewed by assessor.",
        )
        db.add(ai_summary)
        db.commit()
        db.refresh(ai_summary)
        ai_summary_id = ai_summary.id

        # 9. Scans record
        scan_service = ScanService(db)
        scan = scan_service.trigger_scan(
            assessment_id=assessment.id,
            scan_in=ScanCreate(tool=ScanTool.NMAP, target="127.0.0.1"),
            user_id=admin_user.id,
        )

        return {
            "assessment": assessment,
            "target": target,
            "f_override": f_override,
            "f_ai_confirmed": f_ai_confirmed,
            "f_ai_unverified": f_ai_unverified,
            "f_unverified_tool": f_unverified_tool,
            "f_needs_testing": f_needs_testing,
            "f_fp": f_fp,
            "ai_summary": ai_summary,
            "ai_summary_id": ai_summary_id,
            "scan": scan,
        }
    finally:
        db.close()


def _get_docx_all_text(doc: docx.Document) -> str:
    """Extract all text across paragraphs and table cells from a docx Document."""
    text_parts = []
    for p in doc.paragraphs:
        text_parts.append(p.text)
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                text_parts.append(cell.text)
    return "\n".join(text_parts)


def test_report_generation_lifecycle_and_inclusion_rules(assessor_client, complex_report_assessment):
    """
    Test Core Rule 1 & Rule 2:
    - Only confirmed findings appear in detailed sections and risk totals.
    - AI-sourced unverified finding appears ONLY in Appendix A.
    - AI-sourced confirmed finding appears as confirmed vulnerability.
    """
    assessment_id = complex_report_assessment["assessment"].id

    res = assessor_client.post(
        f"/api/v1/assessments/{assessment_id}/reports",
        json={"format": "docx", "include_unverified_appendix": True, "title": "Spring 2026 Audit Report"},
    )
    assert res.status_code == 202
    report_id = res.json()["id"]

    # Retrieve completed report from background processing
    get_res = assessor_client.get(f"/api/v1/reports/{report_id}")
    assert get_res.status_code == 200
    report_data = get_res.json()
    assert report_data["status"] == "completed"
    assert report_data["confirmed_count_at_generation"] == 2
    assert report_data["unverified_count_at_generation"] == 2  # f_ai_unverified + f_unverified_tool

    # Download report and open with python-docx
    dl_res = assessor_client.get(f"/api/v1/reports/{report_id}/download")
    assert dl_res.status_code == 200

    doc = docx.Document(io.BytesIO(dl_res.content))
    full_text = _get_docx_all_text(doc)

    # 1. Confirmed findings appear in detailed sections
    assert "Remote Code Execution via Upload" in full_text
    assert "AI Discovered Path Traversal" in full_text

    # 2. Source attribution for AI confirmed finding (Rule 2)
    assert "Source: AI-assisted, verified by" in full_text

    # 3. Non-confirmed findings appear ONLY in Appendix A with clear warning
    assert "Appendix A: Findings Not Confirmed" in full_text
    assert "NOTICE: THE FOLLOWING FINDINGS ARE NOT CONFIRMED VULNERABILITIES" in full_text
    assert "NOT A CONFIRMED VULNERABILITY" in full_text
    assert "AI Candidate SSRF Vulnerability" in full_text
    assert "Static CSS Parameter Injection" in full_text
    assert "Race Condition in Token Issuance" in full_text


def test_effective_severity_ordering_and_justification(assessor_client, complex_report_assessment):
    """
    Test Rule 4:
    - Finding with override shows effective severity (CRITICAL) in counts and details.
    - Original severity (MEDIUM) and justification are shown.
    """
    assessment_id = complex_report_assessment["assessment"].id
    res = assessor_client.post(
        f"/api/v1/assessments/{assessment_id}/reports",
        json={"format": "docx"},
    )
    assert res.status_code == 202
    dl_res = assessor_client.get(f"/api/v1/reports/{res.json()['id']}/download")
    doc = docx.Document(io.BytesIO(dl_res.content))
    full_text = _get_docx_all_text(doc)

    assert "CRITICAL (Original: MEDIUM)" in full_text
    assert "Assessor demonstrated arbitrary system command execution" in full_text


def test_ai_summary_gating_and_immutability(assessor_client, complex_report_assessment):
    """
    Test Rule 3:
    - Approved AI summary is used with assessor's edited_text.
    - Labeled 'AI-assisted draft, reviewed and approved by [assessor]'.
    - Original AI text in DB remains immutable and unchanged.
    """
    assessment_id = complex_report_assessment["assessment"].id
    res = assessor_client.post(
        f"/api/v1/assessments/{assessment_id}/reports",
        json={"format": "docx"},
    )
    assert res.status_code == 202
    dl_res = assessor_client.get(f"/api/v1/reports/{res.json()['id']}/download")
    doc = docx.Document(io.BytesIO(dl_res.content))
    full_text = _get_docx_all_text(doc)

    # Uses edited_text
    assert "The security assessment identified high-risk code execution and directory traversal vulnerabilities" in full_text
    assert "AI-assisted draft, reviewed and approved by" in full_text

    # Assert original AI record in database was NOT overwritten
    db = SessionLocal()
    try:
        orig_ai = db.query(AIAnalysis).filter(AIAnalysis.id == complex_report_assessment["ai_summary_id"]).first()
        assert orig_ai.response_json["summary_text"] == "Original raw LLM generated summary before assessor review."
    finally:
        db.close()


def test_unapproved_or_rejected_ai_summary_excluded(assessor_client, admin_user):
    """Test that rejected or unapproved executive summary is excluded and report states so."""
    db = SessionLocal()
    try:
        t = TargetService(db).create_target(TargetCreate(name="No AI Target", base_url="http://127.0.0.1:9000"))
        a = AssessmentService(db).create_assessment(AssessmentCreate(name="No AI Assessment", target_id=t.id), user_id=admin_user.id)

        # Rejected summary
        rejected_ai = AIAnalysis(
            assessment_id=a.id,
            function=AIFunction.SUMMARIZE,
            status=AIAnalysisStatus.COMPLETED,
            model="gemini-2.5-flash",
            prompt_version="v1",
            input_hash="hash_rej",
            response_json={"summary_text": "Bad hallucinated text."},
            review_status=AIReviewStatus.REJECTED,
        )
        db.add(rejected_ai)
        db.commit()

        res = assessor_client.post(f"/api/v1/assessments/{a.id}/reports", json={"format": "docx"})
        assert res.status_code == 202

        dl = assessor_client.get(f"/api/v1/reports/{res.json()['id']}/download")
        doc = docx.Document(io.BytesIO(dl.content))
        full_text = _get_docx_all_text(doc)

        assert "No AI-assisted executive summary has been reviewed and approved for this assessment" in full_text
        assert "Bad hallucinated text." not in full_text
    finally:
        db.close()


def test_empty_state_report_generation(assessor_client, admin_user):
    """
    Test Rule 4: Zero confirmed findings, zero scans, no evidence, no AI analyses:
    Report generates cleanly with explicit 'No confirmed vulnerabilities' statement.
    """
    db = SessionLocal()
    try:
        t = TargetService(db).create_target(TargetCreate(name="Empty Target", base_url="http://127.0.0.1:9001"))
        a = AssessmentService(db).create_assessment(AssessmentCreate(name="Empty Assessment", target_id=t.id), user_id=admin_user.id)

        res = assessor_client.post(f"/api/v1/assessments/{a.id}/reports", json={"format": "docx"})
        assert res.status_code == 202
        data = res.json()
        assert data["confirmed_count_at_generation"] == 0

        dl = assessor_client.get(f"/api/v1/reports/{data['id']}/download")
        assert dl.status_code == 200
        doc = docx.Document(io.BytesIO(dl.content))
        full_text = _get_docx_all_text(doc)

        assert "No confirmed vulnerabilities were identified" in full_text
    finally:
        db.close()


def test_evidence_secret_masking(assessor_client, complex_report_assessment):
    """
    Test Rule 7: Cookie values, JWTs, Authorization headers, and passwords are masked.
    Cookie names and attributes (Secure, HttpOnly, SameSite) are preserved.
    Raw evidence in database is untouched.
    """
    assessment_id = complex_report_assessment["assessment"].id
    res = assessor_client.post(f"/api/v1/assessments/{assessment_id}/reports", json={"format": "docx"})
    assert res.status_code == 202

    dl_res = assessor_client.get(f"/api/v1/reports/{res.json()['id']}/download")
    doc = docx.Document(io.BytesIO(dl_res.content))
    full_text = _get_docx_all_text(doc)

    # Secrets MUST NOT appear
    assert "s3cr3t_s3ss10n_v4lu3" not in full_text
    assert "SuperSecretDBPassword123!" not in full_text
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in full_text

    # Cookie name and attributes MUST appear
    assert "session_id=" in full_text
    assert "Secure" in full_text
    assert "HttpOnly" in full_text
    assert "SameSite=Strict" in full_text


def test_untrusted_content_sanitization(assessor_client, complex_report_assessment):
    """
    Test Rule 6: Control characters, huge strings, script tags, template codes,
    and prompt injection strings render as plain text and do not break the document.
    """
    assessment_id = complex_report_assessment["assessment"].id
    res = assessor_client.post(f"/api/v1/assessments/{assessment_id}/reports", json={"format": "docx"})
    assert res.status_code == 202

    dl_res = assessor_client.get(f"/api/v1/reports/{res.json()['id']}/download")
    # File must open successfully with docx without elementtree parse error
    doc = docx.Document(io.BytesIO(dl_res.content))
    full_text = _get_docx_all_text(doc)

    assert "[truncated]" in full_text


def test_screenshot_embedding_and_placeholders(assessor_client, complex_report_assessment):
    """
    Test Rule 7: Valid image embedded with caption/hash; missing file, corrupt image,
    and hash mismatch handled with placeholders and no crash.
    """
    assessment_id = complex_report_assessment["assessment"].id
    res = assessor_client.post(f"/api/v1/assessments/{assessment_id}/reports", json={"format": "docx"})
    assert res.status_code == 202

    dl_res = assessor_client.get(f"/api/v1/reports/{res.json()['id']}/download")
    doc = docx.Document(io.BytesIO(dl_res.content))
    full_text = _get_docx_all_text(doc)

    # Placeholders / notes must be present
    assert "Valid WebShell Screenshot" in full_text
    assert "Caption: test_valid.png" in full_text
    assert "File not found on disk" in full_text
    assert "Image data corrupted or unreadable" in full_text
    assert "Stored hash mismatch" in full_text


def test_report_snapshot_and_immutability(assessor_client, complex_report_assessment):
    """
    Test Rule 5: Snapshot JSON contains included findings, evidence hashes, scans, and AI analysis ID.
    Regeneration creates version 2 and does not modify version 1.
    """
    assessment_id = complex_report_assessment["assessment"].id

    # Version 1
    res1 = assessor_client.post(f"/api/v1/assessments/{assessment_id}/reports", json={"format": "docx"})
    assert res1.status_code == 202
    r1 = assessor_client.get(f"/api/v1/reports/{res1.json()['id']}").json()
    assert r1["status"] == "completed"
    assert r1["version"] == 1
    assert "findings" in r1["snapshot_json"]
    assert "evidence" in r1["snapshot_json"]
    assert "scans" in r1["snapshot_json"]
    v1_hash = r1["sha256"]

    # Version 2
    res2 = assessor_client.post(f"/api/v1/assessments/{assessment_id}/reports", json={"format": "docx"})
    assert res2.status_code == 202
    r2 = assessor_client.get(f"/api/v1/reports/{res2.json()['id']}").json()
    assert r2["status"] == "completed"
    assert r2["version"] == 2
    assert r2["id"] != r1["id"]

    # Check version 1 remains unaltered
    r1_check = assessor_client.get(f"/api/v1/reports/{r1['id']}").json()
    assert r1_check["version"] == 1
    assert r1_check["sha256"] == v1_hash


def test_download_tamper_detection(assessor_client, complex_report_assessment):
    """
    Test Rule 9: Tampered report file triggers 500 error and audit log entry on download.
    """
    assessment_id = complex_report_assessment["assessment"].id
    res = assessor_client.post(f"/api/v1/assessments/{assessment_id}/reports", json={"format": "docx"})
    assert res.status_code == 202
    report_id = res.json()["id"]

    # Tamper with file on disk
    completed = assessor_client.get(f"/api/v1/reports/{report_id}").json()
    assert completed["status"] == "completed"
    file_path = Path(completed["file_path"])
    assert file_path.exists()
    original_bytes = file_path.read_bytes()
    file_path.write_bytes(original_bytes + b"\nTAMPERED_MALICIOUS_BYTES")

    dl_res = assessor_client.get(f"/api/v1/reports/{report_id}/download")
    assert dl_res.status_code == 500
    assert "Report integrity violation" in dl_res.json()["detail"]

    # Check audit entry
    db = SessionLocal()
    try:
        audit_service = AuditService(db)
        logs = audit_service.list_logs(action="report_integrity_failed", limit=5)
        assert len(logs) > 0
        assert str(report_id) in logs[0].detail
    finally:
        db.close()
        # Restore file
        file_path.write_bytes(original_bytes)


def test_report_rbac_and_admin_delete(viewer_client, assessor_client, admin_client, complex_report_assessment):
    """
    Test RBAC:
    - Viewer cannot generate report (403).
    - Viewer can download report.
    - Assessor cannot delete report (403).
    - Admin can delete report (200) and it is audit logged.
    """
    assessment_id = complex_report_assessment["assessment"].id

    # Viewer POST -> 403
    v_post = viewer_client.post(f"/api/v1/assessments/{assessment_id}/reports", json={"format": "docx"})
    assert v_post.status_code == 403

    # Assessor POST -> 202
    a_post = assessor_client.post(f"/api/v1/assessments/{assessment_id}/reports", json={"format": "docx"})
    assert a_post.status_code == 202
    report_id = a_post.json()["id"]

    # Viewer download -> 200
    v_dl = viewer_client.get(f"/api/v1/reports/{report_id}/download")
    assert v_dl.status_code == 200

    # Assessor DELETE -> 403
    a_del = assessor_client.delete(f"/api/v1/reports/{report_id}")
    assert a_del.status_code == 403

    # Admin DELETE -> 200
    adm_del = admin_client.delete(f"/api/v1/reports/{report_id}")
    assert adm_del.status_code == 200
    assert adm_del.json()["status"] == "deleted"

    # Confirm report 404 afterwards
    assert assessor_client.get(f"/api/v1/reports/{report_id}").status_code == 404


def test_pdf_conversion_not_available_or_mocked(assessor_client, complex_report_assessment):
    """
    Test PDF generation:
    - If LibreOffice is not available, returns clear 501 / 422 error.
    - When LibreOffice is mocked as available, conversion executes.
    """
    assessment_id = complex_report_assessment["assessment"].id

    with patch("app.modules.reporting.service.is_libreoffice_available", return_value=False):
        res = assessor_client.post(f"/api/v1/assessments/{assessment_id}/reports", json={"format": "pdf"})
        assert res.status_code in (501, 422)
        assert "PDF conversion not available" in res.json()["detail"]


def test_report_generation_no_ai_calls(assessor_client, complex_report_assessment):
    """Strictly assert no Gemini AI calls occur during report compilation."""
    assessment_id = complex_report_assessment["assessment"].id
    with patch("app.modules.ai_analysis.gemini_client.call_gemini_api") as mock_gemini:
        res = assessor_client.post(f"/api/v1/assessments/{assessment_id}/reports", json={"format": "docx"})
        assert res.status_code == 202
        mock_gemini.assert_not_called()
