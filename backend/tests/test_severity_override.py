import logging
import uuid
import pytest
from pydantic import ValidationError
from fastapi.testclient import TestClient
from app.core.database import SessionLocal
from app.modules.assessments import AssessmentService, AssessmentCreate
from app.modules.findings import FindingService, FindingSeverity, FindingStatus
from app.modules.findings.schemas import FindingCreate
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
            TargetCreate(name=f"Sev Target {uuid.uuid4().hex[:6]}", base_url="http://localhost:3000"), user_id=assessor_user.id
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


def test_cvss_validation_rejects_malformed_v4_and_mismatches(
    assessor_client: TestClient,
    target_and_finding,
):
    """Malformed vectors, CVSS v4.0 vectors, score/vector mismatches, and severity/score mismatches return 422."""
    _, finding_id = target_and_finding
    critical_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # base score 9.8

    # 1. Malformed v3-like vector
    res_malformed = assessor_client.patch(
        f"/api/v1/findings/{finding_id}/severity",
        json={
            "severity": "high",
            "justification": "Adequate justification length for review.",
            "cvss_vector": "CVSS:3.9/garbage",
        },
    )
    assert res_malformed.status_code == 422

    # 2. CVSS v4.0 vector rejected
    res_v4 = assessor_client.patch(
        f"/api/v1/findings/{finding_id}/severity",
        json={
            "severity": "critical",
            "justification": "Adequate justification length for review.",
            "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        },
    )
    assert res_v4.status_code == 422
    assert "4.0" in res_v4.text

    # 3. Score/vector mismatch (vector is 9.8, score is 5.0)
    res_score_mismatch = assessor_client.patch(
        f"/api/v1/findings/{finding_id}/severity",
        json={
            "severity": "critical",
            "justification": "Adequate justification length for review.",
            "cvss_score": 5.0,
            "cvss_vector": critical_vector,
        },
    )
    assert res_score_mismatch.status_code == 422

    # 4. Severity/score mismatch (vector is 9.8 -> critical, but severity is low)
    res_sev_mismatch = assessor_client.patch(
        f"/api/v1/findings/{finding_id}/severity",
        json={
            "severity": "low",
            "justification": "Adequate justification length for review.",
            "cvss_score": 9.8,
            "cvss_vector": critical_vector,
        },
    )
    assert res_sev_mismatch.status_code == 422

    # 5. FindingCreate enforces the same CVSS rules
    with pytest.raises(ValidationError):
        FindingCreate(
            assessment_id=uuid.uuid4(),
            title="Invalid CVSS Finding",
            category="other",
            description="Test",
            severity=FindingSeverity.LOW,
            cvss_score=9.8,
            cvss_vector=critical_vector,
        )


def test_override_without_cvss_clears_old_values(
    assessor_client: TestClient,
    target_and_finding,
):
    """Overriding severity without a new valid vector clears stale cvss_score and cvss_vector."""
    _, finding_id = target_and_finding
    critical_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    # First override sets CVSS 9.8 + vector
    res1 = assessor_client.patch(
        f"/api/v1/findings/{finding_id}/severity",
        json={
            "severity": "critical",
            "justification": "Initial elevation with full CVSS v3.1 vector.",
            "cvss_vector": critical_vector,
        },
    )
    assert res1.status_code == 200
    assert res1.json()["cvss_score"] == 9.8
    assert res1.json()["cvss_vector"] == critical_vector

    # Second override changes severity without CVSS -> clears old CVSS values
    res2 = assessor_client.patch(
        f"/api/v1/findings/{finding_id}/severity",
        json={
            "severity": "medium",
            "justification": "Compensating WAF controls reduce effective risk to medium.",
        },
    )
    assert res2.status_code == 200
    body2 = res2.json()
    assert body2["effective_severity"] == "medium"
    assert body2["cvss_score"] is None
    assert body2["cvss_vector"] is None

    # Severity history records old_cvss=9.8, new_cvss=None, and justification
    hist = assessor_client.get(f"/api/v1/findings/{finding_id}/severity-history").json()
    assert len(hist) == 2
    assert hist[1]["old_severity"] == "critical"
    assert hist[1]["new_severity"] == "medium"
    assert hist[1]["old_cvss"] == 9.8
    assert hist[1]["new_cvss"] is None
    assert "Compensating WAF controls" in hist[1]["justification"]


def test_ingest_candidate_with_invalid_cvss_keeps_finding(assessor_user, caplog):
    """ingest_candidate drops invalid CVSS fields, logs a warning, and still creates the finding."""
    db = SessionLocal()
    try:
        ts = TargetService(db)
        as_svc = AssessmentService(db)
        fs = FindingService(db)

        target = ts.create_target(
            TargetCreate(name=f"Ingest CVSS {uuid.uuid4().hex[:6]}", base_url="http://localhost:3000"),
            user_id=assessor_user.id,
        )
        assessment = as_svc.create_assessment(
            AssessmentCreate(name="Ingest CVSS Assessment", target_id=target.id, created_by=assessor_user.id)
        )

        with caplog.at_level(logging.WARNING):
            finding = fs.ingest_candidate(
                assessment_id=assessment.id,
                title="Scanner Finding With Bad CVSS",
                category="other",
                description="Tool emitted malformed CVSS v4/garbage vector.",
                severity=FindingSeverity.HIGH,
                affected_url="http://localhost:3000/login",
                cvss_score=7.5,
                cvss_vector="CVSS:3.9/garbage",
            )

        assert finding.id is not None
        assert finding.severity == FindingSeverity.HIGH
        assert finding.cvss_score is None
        assert finding.cvss_vector is None
        assert any("Dropping invalid CVSS fields" in rec.message for rec in caplog.records)
    finally:
        db.close()
