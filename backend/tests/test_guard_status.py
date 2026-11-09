import uuid
import pytest
from app.core.database import SessionLocal
from app.modules.assessments import AssessmentService, AssessmentCreate
from app.modules.findings import (
    FindingService,
    FindingCreate,
    FindingSeverity,
    FindingStatus,
    FindingSource,
)
from app.modules.targets import TargetService
from app.modules.targets.schemas import TargetCreate
from app.modules.verification import VerificationService, VerificationCreate, VerificationDecision


def test_no_creation_path_can_set_confirmed():
    """Verify that FindingService.create_finding forbids status other than unverified."""
    db = SessionLocal()
    try:
        service = FindingService(db)
        assessment_id = uuid.uuid4()

        for forbidden_status in (
            FindingStatus.CONFIRMED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.NEEDS_TESTING,
        ):
            with pytest.raises(ValueError) as exc:
                service.create_finding(
                    FindingCreate(
                        assessment_id=assessment_id,
                        title="Bypass Guard Test",
                        category="other",
                        description="Attempting direct status creation",
                        severity=FindingSeverity.HIGH,
                        status=forbidden_status,
                    )
                )
            assert "unverified" in str(exc.value)
    finally:
        db.close()


def test_ai_and_tool_findings_always_start_unverified():
    """Findings from tools or AI must always start unverified."""
    db = SessionLocal()
    try:
        ts = TargetService(db)
        as_svc = AssessmentService(db)
        fs = FindingService(db)

        target = ts.create_target(
            TargetCreate(name=f"Guard Target {uuid.uuid4().hex[:6]}", base_url="http://localhost:3000")
        )
        assessment = as_svc.create_assessment(
            AssessmentCreate(name="Guard Assessment", target_id=target.id)
        )

        # 1. Tool candidate
        tool_f = fs.ingest_candidate(
            assessment_id=assessment.id,
            title="Tool Discovered Finding",
            category="security_headers",
            description="Found by automated scan",
            severity=FindingSeverity.MEDIUM,
            affected_url="http://localhost:3000/",
        )
        assert tool_f.status == FindingStatus.UNVERIFIED
        assert tool_f.source == FindingSource.TOOL

        # 2. AI created finding
        ai_f = fs.create_finding(
            FindingCreate(
                assessment_id=assessment.id,
                title="AI Suggested Finding",
                category="other",
                description="Synthesized by AI analysis",
                severity=FindingSeverity.LOW,
                source=FindingSource.AI,
                status=FindingStatus.UNVERIFIED,
            )
        )
        assert ai_f.status == FindingStatus.UNVERIFIED
        assert ai_f.source == FindingSource.AI
    finally:
        db.close()


def test_rerunning_assessment_does_not_reset_verified_status(assessor_user):
    """Re-running an assessment (Phase 3 deduplication) must NOT reset an already verified finding."""
    db = SessionLocal()
    try:
        ts = TargetService(db)
        as_svc = AssessmentService(db)
        fs = FindingService(db)
        vs = VerificationService(db)

        target = ts.create_target(
            TargetCreate(name=f"Preserve Target {uuid.uuid4().hex[:6]}", base_url="http://localhost:3000")
        )
        assessment = as_svc.create_assessment(
            AssessmentCreate(name="Preserve Assessment", target_id=target.id, created_by=assessor_user.id)
        )

        # Run 1: Ingest candidate with evidence
        f1 = fs.ingest_candidate(
            assessment_id=assessment.id,
            title="Consistent Candidate Finding",
            category="exposed_files",
            description="Exposed env file",
            severity=FindingSeverity.HIGH,
            affected_url="http://localhost:3000/.env",
            evidence_content="DB_PASSWORD=secret",
            evidence_label="Run 1 Leak",
        )
        assert f1.status == FindingStatus.UNVERIFIED

        # Assessor verifies as CONFIRMED
        vs.verify_finding(
            finding_id=f1.id,
            verification_in=VerificationCreate(
                decision=VerificationDecision.CONFIRMED,
                evidence_reviewed=True,
                notes="Confirmed confidential leak in .env file.",
            ),
            user=assessor_user,
        )

        refreshed = fs.get_finding(f1.id)
        assert refreshed.status == FindingStatus.CONFIRMED

        # Run 2: Re-run scan producing identical finding fingerprint
        f2 = fs.ingest_candidate(
            assessment_id=assessment.id,
            title="Consistent Candidate Finding",
            category="exposed_files",
            description="Exposed env file",
            severity=FindingSeverity.HIGH,
            affected_url="http://localhost:3000/.env",
            evidence_content="DB_PASSWORD=secret run 2",
            evidence_label="Run 2 Leak",
        )

        # Must be deduplicated and MUST PRESERVE confirmed status!
        assert f2.id == f1.id
        assert f2.status == FindingStatus.CONFIRMED
    finally:
        db.close()

