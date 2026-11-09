import uuid
import pytest
from fastapi.testclient import TestClient
from app.core.database import SessionLocal
from app.modules.assessments import AssessmentService, AssessmentCreate
from app.modules.findings import FindingService, FindingSeverity, FindingStatus
from app.modules.targets import TargetService
from app.modules.targets.schemas import TargetCreate


@pytest.fixture
def target_and_finding(assessor_user):
    db = SessionLocal()
    try:
        ts = TargetService(db)
        as_svc = AssessmentService(db)
        fs = FindingService(db)

        target = ts.create_target(
            TargetCreate(name=f"Sev Target {uuid.uuid4().hex[:6]}", base_url="http://localhost:3000")
        )
        assessment = as_svc.create_assessment(
            AssessmentCreate(name="Sev Assessment", target_id=target.id, created_by=assessor_user.id)
        )
        finding = fs.ingest_candidate(
            assessment_id=assessment.id,
            title="Default Low Finding",
            category="security_headers",
            description="Informative server banner exposed",
            severity=FindingSeverity.LOW,
            affected_url="http://localhost:3000/",
            cvss_score=2.5,
        )
        return assessment.id, finding.id
    finally:
        db.close()


def test_override_requires_justification_and_valid_cvss(
    assessor_client: TestClient,
    target_and_finding,
):
    """Severity override requires justification meeting minimum length and valid CVSS score range."""
    assessment_id, finding_id = target_and_finding

    # 1. Missing / short justification
    res_short = assessor_client.patch(
        f"/api/v1/findings/{finding_id}/severity",
        json={"severity": "high", "justification": "short"},
    )
    assert res_short.status_code == 422

    # 2. Out of range CVSS score (> 10.0 or < 0.0)
    res_cvss = assessor_client.patch(
        f"/api/v1/findings/{finding_id}/severity",
        json={
            "severity": "high",
            "justification": "Adequate justification length for review.",
            "cvss_score": 12.5,
        },
    )
    assert res_cvss.status_code == 422

    # 3. Invalid CVSS vector prefix
    res_vec = assessor_client.patch(
        f"/api/v1/findings/{finding_id}/severity",
        json={
            "severity": "high",
            "justification": "Adequate justification length for review.",
            "cvss_vector": "INVALID:VECTOR",
        },
    )
    assert res_vec.status_code == 422


def test_override_updates_final_severity_and_creates_history(
    assessor_client: TestClient,
    target_and_finding,
):
    """
    Override updates final_severity and leaves original_severity unchanged.
    Creates append-only severity_changes history.
    """
    assessment_id, finding_id = target_and_finding

    # Initial state
    initial_f = assessor_client.get(f"/api/v1/findings/{finding_id}").json()
    assert initial_f["original_severity"] == "low"
    assert initial_f["final_severity"] is None
    assert initial_f["effective_severity"] == "low"

    # Override to CRITICAL
    res = assessor_client.patch(
        f"/api/v1/findings/{finding_id}/severity",
        json={
            "severity": "critical",
            "justification": "Banner disclosure exposes unpatched zero-day vulnerability.",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
    )
    assert res.status_code == 200
    updated_f = res.json()
    assert updated_f["original_severity"] == "low"
    assert updated_f["final_severity"] == "critical"
    assert updated_f["effective_severity"] == "critical"
    assert updated_f["cvss_score"] == 9.8
    assert "Critical Risk" in updated_f["risk_rating"]

    # Verify history endpoint
    hist_res = assessor_client.get(f"/api/v1/findings/{finding_id}/severity-history")
    assert hist_res.status_code == 200
    history = hist_res.json()
    assert len(history) == 1
    assert history[0]["old_severity"] == "low"
    assert history[0]["new_severity"] == "critical"
    assert history[0]["new_cvss"] == 9.8


def test_effective_severity_used_in_filters_and_summaries(
    assessor_client: TestClient,
    target_and_finding,
):
    """Filters and summaries reflect effective_severity (overridden severity)."""
    assessment_id, finding_id = target_and_finding

    # Override to HIGH
    assessor_client.patch(
        f"/api/v1/findings/{finding_id}/severity",
        json={
            "severity": "high",
            "justification": "Elevating severity based on environmental risk.",
        },
    )

    # Filter by effective_severity = high
    filter_high = assessor_client.get(
        f"/api/v1/assessments/{assessment_id}/findings?effective_severity=high"
    )
    assert filter_high.status_code == 200
    findings = filter_high.json()
    assert any(f["id"] == str(finding_id) for f in findings)

    # Filter by effective_severity = low should not return this finding
    filter_low = assessor_client.get(
        f"/api/v1/assessments/{assessment_id}/findings?effective_severity=low"
    )
    assert not any(f["id"] == str(finding_id) for f in filter_low.json())
