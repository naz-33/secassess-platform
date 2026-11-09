"""Tests for Phase 6 Findings Export functionality."""
import csv
import io
import json
import uuid
import pytest
from unittest.mock import patch

from app.core.database import SessionLocal
from app.modules.targets import TargetService
from app.modules.targets.schemas import TargetCreate, ScopeItemCreate
from app.modules.assessments import AssessmentService
from app.modules.assessments.schemas import AssessmentCreate
from app.modules.findings import FindingService, FindingSeverity, FindingStatus, FindingSource
from app.modules.verification import VerificationService, VerificationCreate, VerificationDecision
from app.modules.audit import AuditService


@pytest.fixture
def export_test_data(admin_user):
    """Fixture with findings designed to test CSV injection, status filters, and secrets omission."""
    db = SessionLocal()
    try:
        target_service = TargetService(db)
        target = target_service.create_target(
            TargetCreate(
                name="Export Target",
                base_url="http://127.0.0.1:8000",
                description="Target for export testing",
                authorization_note="Authorized",
                scope_items=[
                    ScopeItemCreate(asset="http://127.0.0.1:8000", in_scope=True),
                ],
            )
        )

        assessment_service = AssessmentService(db)
        assessment = assessment_service.create_assessment(
            AssessmentCreate(
                name="Export Assessment",
                target_id=target.id,
                created_by=admin_user.id,
            ),
            user_id=admin_user.id,
        )

        finding_service = FindingService(db)
        verification_service = VerificationService(db)

        # 1. Confirmed finding with active formula in title and remediation (CSV Injection test)
        f1 = finding_service.ingest_candidate(
            assessment_id=assessment.id,
            title="=cmd|' /C calc'!A0 Formula in Title",
            category="injection",
            description="Testing formula neutralization",
            severity=FindingSeverity.HIGH,
            affected_url="http://127.0.0.1:8000/calc",
            remediation="@SUM(1+1)*cmd|' /C calc'!A0",
            evidence_content="Raw evidence containing secret password=SuperSecretPassword123!",
            evidence_label="Calc Evidence",
        )
        verification_service.verify_finding(
            finding_id=f1.id,
            verification_in=VerificationCreate(
                decision=VerificationDecision.CONFIRMED,
                notes="Confirmed injection test",
                evidence_reviewed=True,
            ),
            user=admin_user,
        )

        # 2. Confirmed finding starting with plus (+) and minus (-)
        f2 = finding_service.ingest_candidate(
            assessment_id=assessment.id,
            title="+123456789 Phone Number Formula",
            category="info_leak",
            description="-DANGEROUS_CLI_OPTION in description",
            severity=FindingSeverity.MEDIUM,
            affected_url="http://127.0.0.1:8000/phone",
            remediation="-Patch software immediately",
            evidence_content="Authorization: Bearer secret_jwt_token_here",
            evidence_label="Phone Evidence",
        )
        verification_service.verify_finding(
            finding_id=f2.id,
            verification_in=VerificationCreate(
                decision=VerificationDecision.CONFIRMED,
                notes="Confirmed phone leak",
                evidence_reviewed=True,
            ),
            user=admin_user,
        )

        # 3. Unverified finding
        f3 = finding_service.ingest_candidate(
            assessment_id=assessment.id,
            title="Unverified Candidate",
            category="other",
            description="A candidate finding not yet verified",
            severity=FindingSeverity.LOW,
            affected_url="http://127.0.0.1:8000/candidate",
            evidence_content="Evidence content",
            evidence_label="Candidate Evidence",
        )

        # 4. False positive finding
        f4 = finding_service.ingest_candidate(
            assessment_id=assessment.id,
            title="False Positive Header Issue",
            category="security_headers",
            description="Not an actual bug",
            severity=FindingSeverity.LOW,
            affected_url="http://127.0.0.1:8000/fp",
            evidence_content="Evidence content",
            evidence_label="FP Evidence",
        )
        verification_service.verify_finding(
            finding_id=f4.id,
            verification_in=VerificationCreate(
                decision=VerificationDecision.FALSE_POSITIVE,
                notes="Assessor verified this is a false positive header.",
                evidence_reviewed=True,
            ),
            user=admin_user,
        )

        return {
            "assessment": assessment,
            "f1": f1,
            "f2": f2,
            "f3": f3,
            "f4": f4,
        }
    finally:
        db.close()


def test_export_viewer_forbidden(viewer_client, export_test_data):
    """Assert viewer role is forbidden from exporting findings."""
    assessment_id = export_test_data["assessment"].id
    res = viewer_client.get(f"/api/v1/assessments/{assessment_id}/findings/export")
    assert res.status_code == 403


def test_export_default_confirmed_only_csv(assessor_client, export_test_data):
    """Test default export is CSV format and includes ONLY confirmed findings."""
    assessment_id = export_test_data["assessment"].id
    res = assessor_client.get(f"/api/v1/assessments/{assessment_id}/findings/export")
    assert res.status_code == 200
    assert "text/csv" in res.headers["content-type"]
    assert "attachment" in res.headers["content-disposition"]
    assert res.headers.get("x-content-type-options") == "nosniff"

    csv_text = res.text
    reader = csv.DictReader(io.StringIO(csv_text))
    rows = list(reader)

    # Only f1 and f2 are confirmed!
    assert len(rows) == 2
    for r in rows:
        assert r["status"] == "confirmed"
        assert r["verified"] in ("True", "true")

    # CSV Injection Neutralization check:
    # Cell starting with '=' must be prefixed with single quote
    calc_row = [r for r in rows if "calc" in r["title"].lower()][0]
    assert calc_row["title"].startswith("'=")
    assert calc_row["remediation"].startswith("'@")

    # Cell starting with '+' and '-' must be prefixed with single quote
    phone_row = [r for r in rows if "phone" in r["title"].lower()][0]
    assert phone_row["title"].startswith("'+")
    assert phone_row["remediation"].startswith("'-")

    # Raw secrets must NOT be in the export output
    assert "SuperSecretPassword123!" not in csv_text
    assert "secret_jwt_token_here" not in csv_text


def test_export_json_format(assessor_client, export_test_data):
    """Test JSON export format."""
    assessment_id = export_test_data["assessment"].id
    res = assessor_client.get(f"/api/v1/assessments/{assessment_id}/findings/export?format=json")
    assert res.status_code == 200
    assert "application/json" in res.headers["content-type"]

    items = res.json()
    assert len(items) == 2
    for it in items:
        assert it["status"] == "confirmed"
        assert it["verified"] is True
        assert "SuperSecretPassword123!" not in str(it)


def test_export_with_custom_status_filter(assessor_client, export_test_data):
    """Test exporting non-confirmed findings when explicitly requested."""
    assessment_id = export_test_data["assessment"].id

    # 1. Unverified filter
    res_unv = assessor_client.get(f"/api/v1/assessments/{assessment_id}/findings/export?format=json&status=unverified")
    assert res_unv.status_code == 200
    unv_items = res_unv.json()
    assert len(unv_items) == 1
    assert unv_items[0]["status"] == "unverified"
    assert unv_items[0]["verified"] is False

    # 2. False positive filter
    res_fp = assessor_client.get(f"/api/v1/assessments/{assessment_id}/findings/export?format=json&status=false_positive")
    assert res_fp.status_code == 200
    fp_items = res_fp.json()
    assert len(fp_items) == 1
    assert fp_items[0]["status"] == "false_positive"
    assert fp_items[0]["verified"] is False

    # 3. All filter
    res_all = assessor_client.get(f"/api/v1/assessments/{assessment_id}/findings/export?format=json&status=all")
    assert res_all.status_code == 200
    all_items = res_all.json()
    assert len(all_items) == 4


def test_export_invalid_format_or_status(assessor_client, export_test_data):
    """Assert 422 for unsupported export format or invalid status."""
    assessment_id = export_test_data["assessment"].id
    res_fmt = assessor_client.get(f"/api/v1/assessments/{assessment_id}/findings/export?format=xml")
    assert res_fmt.status_code == 422

    res_st = assessor_client.get(f"/api/v1/assessments/{assessment_id}/findings/export?status=invalid_status")
    assert res_st.status_code == 422


def test_export_audit_logged(assessor_client, export_test_data):
    """Assert findings export triggers an audit log entry."""
    assessment_id = export_test_data["assessment"].id
    res = assessor_client.get(f"/api/v1/assessments/{assessment_id}/findings/export?format=csv")
    assert res.status_code == 200

    db = SessionLocal()
    try:
        audit_service = AuditService(db)
        logs = audit_service.list_logs(action="findings_exported", limit=5)
        assert len(logs) > 0
        latest = logs[0]
        assert str(assessment_id) in latest.detail
        assert "csv" in latest.detail
    finally:
        db.close()


def test_export_no_ai_calls(assessor_client, export_test_data):
    """Strictly assert no Gemini AI calls during export."""
    assessment_id = export_test_data["assessment"].id
    with patch("app.modules.ai_analysis.gemini_client.call_gemini_api") as mock_gemini:
        res = assessor_client.get(f"/api/v1/assessments/{assessment_id}/findings/export?format=json")
        assert res.status_code == 200
        mock_gemini.assert_not_called()

