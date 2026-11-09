import uuid
import pytest
from app.core.database import SessionLocal
from app.modules.findings import (
    FindingService,
    FindingCreate,
    FindingSeverity,
    FindingStatus,
    FindingSource,
    EvidenceType,
)
from app.modules.assessments import AssessmentService, AssessmentCreate
from app.modules.targets import TargetService
from app.modules.targets.schemas import TargetCreate


@pytest.fixture
def db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_finding_always_created_unverified_guard(db_session):
    """Service-level guard: attempt to set status to confirmed in Phase 3 must raise ValueError."""
    service = FindingService(db_session)

    # Valid unverified finding creation
    assessment_id = uuid.uuid4()
    with pytest.raises(ValueError) as exc_info:
        service.create_finding(
            FindingCreate(
                assessment_id=assessment_id,
                title="Test Guard Finding",
                category="security_headers",
                description="Testing status guard",
                severity=FindingSeverity.MEDIUM,
                status=FindingStatus.CONFIRMED,  # FORBIDDEN in Phase 3!
            )
        )
    assert "must always be created with status 'unverified'" in str(exc_info.value)


def test_finding_deduplication_and_evidence_attachment(db_session):
    """
    Ingesting identical candidates across scan runs must de-duplicate into one finding,
    appending evidence rather than duplicating the finding row.
    """
    target_service = TargetService(db_session)
    ass_service = AssessmentService(db_session)
    finding_service = FindingService(db_session)

    # Create target and assessment
    target = target_service.create_target(
        TargetCreate(
            name=f"Deduplication Target {uuid.uuid4().hex[:6]}",
            base_url="http://localhost:3000",
        )
    )
    assessment = ass_service.create_assessment(
        AssessmentCreate(
            name="Deduplication Assessment",
            target_id=target.id,
        )
    )

    # 1. Ingest candidate finding (run 1)
    f1 = finding_service.ingest_candidate(
        assessment_id=assessment.id,
        title="Missing Content-Security-Policy Header",
        category="security_headers",
        description="CSP header is missing.",
        severity=FindingSeverity.MEDIUM,
        affected_url="http://localhost:3000/",
        evidence_content="Raw transcript 1: No CSP found",
        evidence_label="Run 1 Evidence",
    )
    assert f1.status == FindingStatus.UNVERIFIED
    assert len(f1.evidences) == 1
    initial_finding_id = f1.id

    # 2. Ingest identical candidate finding (run 2)
    f2 = finding_service.ingest_candidate(
        assessment_id=assessment.id,
        title="Missing Content-Security-Policy Header",
        category="security_headers",
        description="CSP header is missing.",
        severity=FindingSeverity.MEDIUM,
        affected_url="http://localhost:3000/",
        evidence_content="Raw transcript 2: Still no CSP found",
        evidence_label="Run 2 Evidence",
    )

    # Must be the exact same finding ID!
    assert f2.id == initial_finding_id

    # Assessment must contain exactly 1 finding
    findings_list = finding_service.list_findings(assessment.id)
    assert len(findings_list) == 1
    assert findings_list[0].id == initial_finding_id

    # Evidence count must be 2
    evidences = finding_service.list_evidence_for_finding(initial_finding_id)
    assert len(evidences) == 2
    contents = [e.content for e in evidences]
    assert "Raw transcript 1: No CSP found" in contents
    assert "Raw transcript 2: Still no CSP found" in contents


def test_evidence_stored_unchanged_and_retrievable(db_session):
    """Raw HTTP transcript evidence must be stored exactly as captured."""
    target_service = TargetService(db_session)
    ass_service = AssessmentService(db_session)
    finding_service = FindingService(db_session)

    target = target_service.create_target(
        TargetCreate(
            name=f"Evidence Target {uuid.uuid4().hex[:6]}",
            base_url="http://localhost:3000",
        )
    )
    assessment = ass_service.create_assessment(
        AssessmentCreate(
            name="Evidence Assessment",
            target_id=target.id,
        )
    )

    raw_transcript = (
        "> GET /test HTTP/1.1\r\n> Host: localhost\r\n\r\n< HTTP/1.1 200 OK\r\n< Server: Custom\r\n\r\nHello"
    )
    finding = finding_service.ingest_candidate(
        assessment_id=assessment.id,
        title="Server Header Disclosed",
        category="information_disclosure",
        description="Server header is disclosed.",
        severity=FindingSeverity.INFO,
        affected_url="http://localhost:3000/test",
        evidence_content=raw_transcript,
        evidence_label="Raw HTTP Response",
    )

    assert len(finding.evidences) == 1
    evidence_id = finding.evidences[0].id

    fetched_ev = finding_service.get_evidence(evidence_id)
    assert fetched_ev is not None
    assert fetched_ev.content == raw_transcript
    assert fetched_ev.label == "Raw HTTP Response"
    assert fetched_ev.type == EvidenceType.REQUEST_RESPONSE

