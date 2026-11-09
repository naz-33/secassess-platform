import uuid
from fastapi.testclient import TestClient
from app.core.database import SessionLocal
from app.modules.assessments import AssessmentService, AssessmentCreate
from app.modules.findings import FindingService, FindingSeverity, EvidenceType
from app.modules.targets import TargetService
from app.modules.targets.schemas import TargetCreate


def test_findings_summary_metrics(
    assessor_client: TestClient,
    assessor_user,
):
    """
    Test summary aggregations:
    - Counts by status
    - Counts by effective severity for confirmed findings only
    - Unverified vs verified counts
    - Verification progress ratio
    """
    db = SessionLocal()
    try:
        ts = TargetService(db)
        as_svc = AssessmentService(db)
        fs = FindingService(db)

        target = ts.create_target(
            TargetCreate(name=f"Summary Target {uuid.uuid4().hex[:6]}", base_url="http://localhost:3000")
        )
        assessment = as_svc.create_assessment(
            AssessmentCreate(name="Summary Assessment", target_id=target.id, created_by=assessor_user.id)
        )

        # Create 3 candidate findings
        f1 = fs.ingest_candidate(
            assessment_id=assessment.id,
            title="Finding 1 High",
            category="security_headers",
            description="Missing HSTS",
            severity=FindingSeverity.HIGH,
            affected_url="http://localhost:3000/",
            evidence_content="No Strict-Transport-Security header",
        )
        f2 = fs.ingest_candidate(
            assessment_id=assessment.id,
            title="Finding 2 Medium",
            category="exposed_files",
            description="robots.txt reveals paths",
            severity=FindingSeverity.MEDIUM,
            affected_url="http://localhost:3000/robots.txt",
            evidence_content="Disallow: /secret",
        )
        f3 = fs.ingest_candidate(
            assessment_id=assessment.id,
            title="Finding 3 Low",
            category="information_disclosure",
            description="Server header reveals Nginx version",
            severity=FindingSeverity.LOW,
            affected_url="http://localhost:3000/",
            evidence_content="Server: nginx/1.18.0",
        )
        f1_id = f1.id
        f2_id = f2.id
        f3_id = f3.id
        assessment_id = assessment.id
    finally:
        db.close()

    # Step 1: Initial summary (all 3 unverified)
    res1 = assessor_client.get(f"/api/v1/assessments/{assessment_id}/findings/summary")
    assert res1.status_code == 200
    s1 = res1.json()
    assert s1["total"] == 3
    assert s1["unverified_count"] == 3
    assert s1["verified_count"] == 0
    assert s1["verification_progress"] == 0.0
    assert s1["confirmed_by_effective_severity"]["high"] == 0
    assert s1["by_status"]["unverified"] == 3

    # Step 2: Confirm Finding 1 with severity override from HIGH to CRITICAL
    assessor_client.patch(
        f"/api/v1/findings/{f1_id}/severity",
        json={
            "severity": "critical",
            "justification": "Upgraded after assessor review confirmed remote exploitation.",
        },
    )
    assessor_client.post(
        f"/api/v1/findings/{f1_id}/verify",
        json={
            "decision": "confirmed",
            "evidence_reviewed": True,
            "notes": "Confirmed and upgraded.",
        },
    )

    # Step 3: Reject Finding 2 as false_positive
    assessor_client.post(
        f"/api/v1/findings/{f2_id}/verify",
        json={
            "decision": "false_positive",
            "notes": "robots.txt is intentional public policy.",
        },
    )

    # Step 4: Summary after 2 verifications (1 confirmed, 1 false positive, 1 unverified)
    res2 = assessor_client.get(f"/api/v1/assessments/{assessment_id}/findings/summary")
    assert res2.status_code == 200
    s2 = res2.json()
    assert s2["total"] == 3
    assert s2["unverified_count"] == 1
    assert s2["verified_count"] == 2
    assert s2["verification_progress"] == 0.6667
    assert s2["by_status"]["confirmed"] == 1
    assert s2["by_status"]["false_positive"] == 1
    assert s2["by_status"]["unverified"] == 1

    # Confirmed findings by EFFECTIVE severity: Finding 1 was upgraded to CRITICAL!
    assert s2["confirmed_by_effective_severity"]["critical"] == 1
    assert s2["confirmed_by_effective_severity"]["high"] == 0
    assert s2["confirmed_by_effective_severity"]["medium"] == 0
