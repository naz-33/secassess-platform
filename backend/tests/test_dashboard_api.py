"""Tests for Phase 6 Dashboard API endpoints."""
import uuid
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.modules.targets import TargetService
from app.modules.targets.schemas import TargetCreate, ScopeItemCreate
from app.modules.assessments import AssessmentService
from app.modules.assessments.schemas import AssessmentCreate
from app.modules.findings import FindingService, FindingCreate, FindingSeverity, FindingStatus, FindingSource
from app.modules.verification import VerificationService, VerificationCreate, VerificationDecision
from app.modules.scans import ScanService, ScanCreate, ScanTool
from app.modules.recon import ReconService


@pytest.fixture
def assessment_with_dashboard_data(admin_user):
    """Fixture providing a complete assessment environment with targets, findings, scans, and assets."""
    db = SessionLocal()
    try:
        target_service = TargetService(db)
        target = target_service.create_target(
            TargetCreate(
                name="Dashboard Target System",
                base_url="http://127.0.0.1:8080",
                description="Target for dashboard metrics testing",
                authorization_note="Authorized by lab instructor",
                scope_items=[
                    ScopeItemCreate(asset="127.0.0.1", in_scope=True, notes="Localhost IP"),
                    ScopeItemCreate(asset="http://127.0.0.1:8080", in_scope=True, notes="Main web app"),
                    ScopeItemCreate(asset="http://127.0.0.1:9090", in_scope=False, notes="Out of scope admin"),
                ],
            )
        )

        assessment_service = AssessmentService(db)
        assessment = assessment_service.create_assessment(
            AssessmentCreate(
                name="Dashboard Metrics Assessment",
                target_id=target.id,
                created_by=admin_user.id,
            ),
            user_id=admin_user.id,
        )

        finding_service = FindingService(db)
        verification_service = VerificationService(db)

        # 1. Confirmed High Finding
        f1 = finding_service.ingest_candidate(
            assessment_id=assessment.id,
            title="Confirmed SQL Injection",
            category="sql_injection",
            description="SQL Injection found in search endpoint",
            severity=FindingSeverity.HIGH,
            affected_url="http://127.0.0.1:8080/search",
            evidence_content="HTTP/1.1 500 Syntax error near ''",
            evidence_label="SQL Error",
        )
        verification_service.verify_finding(
            finding_id=f1.id,
            verification_in=VerificationCreate(
                decision=VerificationDecision.CONFIRMED,
                notes="Verified with sql payload",
                evidence_reviewed=True,
            ),
            user=admin_user,
        )

        # 2. Confirmed Medium Finding
        f2 = finding_service.ingest_candidate(
            assessment_id=assessment.id,
            title="Missing Security Headers",
            category="security_headers",
            description="Strict-Transport-Security header missing",
            severity=FindingSeverity.MEDIUM,
            affected_url="http://127.0.0.1:8080/",
            evidence_content="HTTP/1.1 200 OK\nServer: nginx",
            evidence_label="Headers",
        )
        verification_service.verify_finding(
            finding_id=f2.id,
            verification_in=VerificationCreate(
                decision=VerificationDecision.CONFIRMED,
                notes="Verified missing HSTS header",
                evidence_reviewed=True,
            ),
            user=admin_user,
        )

        # 3. Unverified Finding
        f3 = finding_service.ingest_candidate(
            assessment_id=assessment.id,
            title="Potential Information Disclosure",
            category="information_disclosure",
            description="Exposed phpinfo page",
            severity=FindingSeverity.LOW,
            affected_url="http://127.0.0.1:8080/info.php",
            evidence_content="PHP Version 8.1",
            evidence_label="PHP Info",
        )

        # 4. False Positive Finding
        f4 = finding_service.ingest_candidate(
            assessment_id=assessment.id,
            title="Potential XSS on Static Resource",
            category="xss",
            description="False positive reflected string in image parameter",
            severity=FindingSeverity.MEDIUM,
            affected_url="http://127.0.0.1:8080/img.png",
            evidence_content="Static PNG content",
            evidence_label="PNG",
        )
        verification_service.verify_finding(
            finding_id=f4.id,
            verification_in=VerificationCreate(
                decision=VerificationDecision.FALSE_POSITIVE,
                notes="Static image handler; parameter not reflected in HTML context.",
                evidence_reviewed=True,
            ),
            user=admin_user,
        )

        # Create real Scan record
        scan_service = ScanService(db)
        scan = scan_service.trigger_scan(
            assessment_id=assessment.id,
            scan_in=ScanCreate(tool=ScanTool.NMAP, target="127.0.0.1"),
            user_id=admin_user.id,
        )

        # Recon Assets
        recon_service = ReconService(db)
        recon_service.create_assets_from_scan(
            assessment_id=assessment.id,
            scan_id=scan.id,
            parsed_items=[
                {"type": "host", "value": "127.0.0.1", "details": {"hostname": "localhost"}},
                {"type": "port", "value": "8080/tcp", "details": {"state": "open"}},
                {"type": "service", "value": "http", "details": {"name": "http-alt"}},
                {"type": "endpoint", "value": "/search", "details": {}},
            ],
        )

        return {
            "target": target,
            "assessment": assessment,
            "findings": [f1, f2, f3, f4],
        }
    finally:
        db.close()


def test_assessment_dashboard_unauthenticated(unauth_client, assessment_with_dashboard_data):
    """Assert unauthenticated requests to dashboard endpoints return 401."""
    assessment_id = assessment_with_dashboard_data["assessment"].id
    res = unauth_client.get(f"/api/v1/assessments/{assessment_id}/dashboard")
    assert res.status_code == 401

    res_global = unauth_client.get("/api/v1/dashboard")
    assert res_global.status_code == 401


def test_assessment_dashboard_viewer_can_read(viewer_client, assessment_with_dashboard_data):
    """Assert viewers have read access to consolidated assessment dashboard."""
    assessment_id = assessment_with_dashboard_data["assessment"].id
    res = viewer_client.get(f"/api/v1/assessments/{assessment_id}/dashboard")
    assert res.status_code == 200

    data = res.json()
    assert data["assessment"]["id"] == str(assessment_id)
    assert data["assessment"]["name"] == "Dashboard Metrics Assessment"

    # Scope counts
    assert data["scope"]["in_scope"] == 2
    assert data["scope"]["out_of_scope"] == 1
    assert data["scope"]["total"] == 3

    # Findings summary
    f_sum = data["findings"]
    assert f_sum["total"] == 4
    assert f_sum["by_status"]["confirmed"] == 2
    assert f_sum["by_status"]["unverified"] == 1
    assert f_sum["by_status"]["false_positive"] == 1

    # Zero-filled severity buckets verification
    for sev in ["critical", "high", "medium", "low", "info"]:
        assert sev in f_sum["by_severity"]
        assert sev in f_sum["confirmed_by_effective_severity"]

    # Confirmed counts: 1 high, 1 medium, 0 critical, 0 low, 0 info
    assert f_sum["confirmed_by_effective_severity"]["high"] == 1
    assert f_sum["confirmed_by_effective_severity"]["medium"] == 1
    assert f_sum["confirmed_by_effective_severity"]["critical"] == 0
    assert f_sum["confirmed_by_effective_severity"]["low"] == 0
    assert f_sum["confirmed_by_effective_severity"]["info"] == 0

    # Verification progress (3 verified: 2 confirmed + 1 false_positive / 4 total)
    assert f_sum["verified_count"] == 3
    assert f_sum["unverified_count"] == 1
    assert f_sum["verification_progress"] == 0.75

    # Top findings (confirmed only, ordered by highest severity)
    assert len(data["top_findings"]) == 2
    assert data["top_findings"][0]["severity"] == "high"
    assert data["top_findings"][0]["title"] == "Confirmed SQL Injection"
    assert data["top_findings"][1]["severity"] == "medium"

    # Assets summary
    assets = data["assets"]
    assert assets["total"] == 4
    assert assets["by_type"]["host"] == 1
    assert assets["by_type"]["port"] == 1
    assert assets["by_type"]["service"] == 1
    assert assets["by_type"]["endpoint"] == 1

    # AI counts
    ai = data["ai"]
    assert "total" in ai
    assert "has_approved_executive_summary" in ai

    # Recent activity
    assert isinstance(data["recent_activity"], list)


def test_global_dashboard_overview(viewer_client, assessment_with_dashboard_data):
    """Test global overview across assessments with pagination and aggregated counts."""
    res = viewer_client.get("/api/v1/dashboard?limit=10&offset=0")
    assert res.status_code == 200

    data = res.json()
    assert data["total_assessments"] >= 1
    assert data["total_targets"] >= 1
    assert data["total_findings"] >= 4
    assert "findings_by_severity" in data
    assert "findings_by_status" in data
    assert len(data["assessments"]) >= 1

    # Verify zero-filled severity keys
    for sev in ["critical", "high", "medium", "low", "info"]:
        assert sev in data["findings_by_severity"]

    # Check pagination metadata
    assert data["pagination"]["limit"] == 10
    assert data["pagination"]["offset"] == 0


def test_dashboard_no_ai_invocations(assessor_client, assessment_with_dashboard_data):
    """Strictly assert that Gemini LLM is never invoked during dashboard queries."""
    assessment_id = assessment_with_dashboard_data["assessment"].id
    with patch("app.modules.ai_analysis.gemini_client.call_gemini_api") as mock_gemini:
        res1 = assessor_client.get(f"/api/v1/assessments/{assessment_id}/dashboard")
        assert res1.status_code == 200

        res2 = assessor_client.get("/api/v1/dashboard")
        assert res2.status_code == 200

        mock_gemini.assert_not_called()
