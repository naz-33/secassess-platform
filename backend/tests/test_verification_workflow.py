import uuid
import pytest
from fastapi.testclient import TestClient
from app.core.database import SessionLocal
from app.modules.assessments import AssessmentService, AssessmentCreate
from app.modules.findings import FindingService, FindingSeverity, FindingStatus, EvidenceType
from app.modules.targets import TargetService
from app.modules.targets.schemas import TargetCreate


@pytest.fixture
def test_finding_with_evidence(assessor_user):
    db = SessionLocal()
    try:
        ts = TargetService(db)
        as_svc = AssessmentService(db)
        fs = FindingService(db)

        target = ts.create_target(
            TargetCreate(name=f"Verif Target {uuid.uuid4().hex[:6]}", base_url="http://localhost:3000")
        )
        assessment = as_svc.create_assessment(
            AssessmentCreate(name="Verif Assessment", target_id=target.id, created_by=assessor_user.id)
        )
        finding = fs.ingest_candidate(
            assessment_id=assessment.id,
            title="Exposed Git Directory",
            category="exposed_files",
            description="Exposed .git repository found",
            severity=FindingSeverity.HIGH,
            affected_url="http://localhost:3000/.git/HEAD",
            evidence_content="ref: refs/heads/main",
            evidence_label="Git HEAD content",
            evidence_type=EvidenceType.OUTPUT,
        )
        return finding.id
    finally:
        db.close()


@pytest.fixture
def test_finding_without_evidence(assessor_user):
    db = SessionLocal()
    try:
        ts = TargetService(db)
        as_svc = AssessmentService(db)
        fs = FindingService(db)

        target = ts.create_target(
            TargetCreate(name=f"No Evidence Target {uuid.uuid4().hex[:6]}", base_url="http://localhost:3000")
        )
        assessment = as_svc.create_assessment(
            AssessmentCreate(name="No Evidence Assessment", target_id=target.id, created_by=assessor_user.id)
        )
        finding = fs.ingest_candidate(
            assessment_id=assessment.id,
            title="Candidate Finding No Evidence",
            category="information_disclosure",
            description="Lacks supporting evidence item",
            severity=FindingSeverity.LOW,
            affected_url="http://localhost:3000/info",
            evidence_content=None,
        )
        return finding.id
    finally:
        db.close()


def test_assessor_can_confirm_with_evidence(
    assessor_client: TestClient,
    test_finding_with_evidence,
):
    """Assessor can confirm a finding when evidence is reviewed and exists."""
    finding_id = test_finding_with_evidence

    res = assessor_client.post(
        f"/api/v1/findings/{finding_id}/verify",
        json={
            "decision": "confirmed",
            "notes": "Verified .git repository is publicly accessible.",
            "evidence_reviewed": True,
        },
    )
    assert res.status_code == 201, res.text
    verif = res.json()
    assert verif["decision"] == "confirmed"
    assert verif["evidence_reviewed"] is True

    # Check updated finding
    finding_res = assessor_client.get(f"/api/v1/findings/{finding_id}")
    assert finding_res.status_code == 200
    finding_data = finding_res.json()
    assert finding_data["status"] == "confirmed"
    assert finding_data["verified_by"] is not None
    assert finding_data["verified_at"] is not None


def test_confirm_rejected_without_evidence_or_not_reviewed(
    assessor_client: TestClient,
    test_finding_without_evidence,
    test_finding_with_evidence,
):
    """Confirmation is rejected if evidence_reviewed=False or finding has no evidence."""
    # 1. evidence_reviewed is False
    res1 = assessor_client.post(
        f"/api/v1/findings/{test_finding_with_evidence}/verify",
        json={"decision": "confirmed", "evidence_reviewed": False},
    )
    assert res1.status_code == 422
    assert "evidence_reviewed" in res1.json()["detail"].lower()

    # 2. Finding has 0 evidence items
    res2 = assessor_client.post(
        f"/api/v1/findings/{test_finding_without_evidence}/verify",
        json={"decision": "confirmed", "evidence_reviewed": True},
    )
    assert res2.status_code == 422
    assert "at least one supporting evidence item" in res2.json()["detail"].lower()


def test_false_positive_and_needs_testing_require_notes(
    assessor_client: TestClient,
    test_finding_with_evidence,
):
    """false_positive and needs_testing require non-empty notes meeting minimum length."""
    finding_id = test_finding_with_evidence

    # Missing notes
    res_empty = assessor_client.post(
        f"/api/v1/findings/{finding_id}/verify",
        json={"decision": "false_positive", "notes": ""},
    )
    assert res_empty.status_code == 422

    # Short notes (< 10 chars)
    res_short = assessor_client.post(
        f"/api/v1/findings/{finding_id}/verify",
        json={"decision": "needs_testing", "notes": "too short"},
    )
    assert res_short.status_code == 422

    # Valid notes
    res_valid = assessor_client.post(
        f"/api/v1/findings/{finding_id}/verify",
        json={"decision": "false_positive", "notes": "Header is intentionally omitted behind reverse proxy."},
    )
    assert res_valid.status_code == 201
    assert res_valid.json()["decision"] == "false_positive"


def test_append_only_history_and_reopening(
    assessor_client: TestClient,
    test_finding_with_evidence,
):
    """
    Any decision can be followed by a new decision.
    History is append-only, ordered chronologically, and status reflects latest decision.
    """
    finding_id = test_finding_with_evidence

    # Decision 1: false_positive
    assessor_client.post(
        f"/api/v1/findings/{finding_id}/verify",
        json={"decision": "false_positive", "notes": "Assumed false positive initially."},
    )

    # Decision 2: needs_testing
    assessor_client.post(
        f"/api/v1/findings/{finding_id}/verify",
        json={"decision": "needs_testing", "notes": "Re-opening for secondary manual testing."},
    )

    # Decision 3: confirmed
    assessor_client.post(
        f"/api/v1/findings/{finding_id}/verify",
        json={"decision": "confirmed", "evidence_reviewed": True, "notes": "Confirmed on testing."},
    )

    # Status must reflect latest decision
    f_res = assessor_client.get(f"/api/v1/findings/{finding_id}")
    assert f_res.json()["status"] == "confirmed"

    # Verifications list must contain all 3 rows in order
    history_res = assessor_client.get(f"/api/v1/findings/{finding_id}/verifications")
    assert history_res.status_code == 200
    history = history_res.json()
    assert len(history) == 3
    assert history[0]["decision"] == "false_positive"
    assert history[1]["decision"] == "needs_testing"
    assert history[2]["decision"] == "confirmed"

