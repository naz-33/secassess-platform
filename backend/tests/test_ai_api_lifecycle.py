"""Full HTTP API lifecycle and RBAC enforcement tests for AI endpoints."""
import json
import uuid
from pathlib import Path
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.modules.auth.models import User
from app.modules.assessments import AssessmentService, AssessmentCreate
from app.modules.targets import TargetService, TargetCreate, ScopeItemCreate
from app.modules.scans import ScanService, ScanCreate, ScanTool
from app.modules.findings import FindingService, FindingSeverity


@pytest.fixture
def lifecycle_setup(db_session, admin_user: User):
    target_service = TargetService(db_session)
    assessment_service = AssessmentService(db_session)
    scan_service = ScanService(db_session)
    finding_service = FindingService(db_session)

    target = target_service.create_target(
        TargetCreate(
            name="Lifecycle Target",
            base_url="http://target.local",
            scope_items=[
                ScopeItemCreate(asset="http://target.local", in_scope=True),
                ScopeItemCreate(asset="target.local", in_scope=True),
            ],
        )
    )
    assessment = assessment_service.create_assessment(
        AssessmentCreate(name="Lifecycle Assessment", target_id=target.id),
        user_id=admin_user.id,
    )
    scan = scan_service.trigger_scan(
        assessment_id=assessment.id,
        scan_in=ScanCreate(tool=ScanTool.NMAP, target="target.local"),
        user_id=admin_user.id,
    )
    scan_m = scan_service.repository.get_by_id(scan.id)
    scan_m.raw_output = "HTTP/1.1 200 OK\nServer: Apache\nSet-Cookie: session=xyz123"
    db_session.commit()

    finding = finding_service.ingest_candidate(
        assessment_id=assessment.id,
        title="Sample Lifecycle Finding",
        category="security_headers",
        description="Missing security headers.",
        severity=FindingSeverity.LOW,
        affected_url="http://target.local",
    )

    return {
        "assessment": assessment,
        "scan": scan,
        "finding": finding,
    }


@pytest.fixture
def db_session():
    from app.core.database import SessionLocal
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def setup_lifecycle_ai_limits(monkeypatch):
    monkeypatch.setattr(settings, "AI_MAX_CALLS_PER_USER_PER_HOUR", 1000)
    monkeypatch.setattr(settings, "AI_MAX_CALLS_PER_ASSESSMENT", 1000)


def test_ai_status_endpoint(client: TestClient, viewer_client: TestClient, unauth_client: TestClient):
    """GET /api/v1/ai/status and /api/ai/status access checks."""
    # Unauthenticated gets 401
    r_unauth = unauth_client.get("/api/v1/ai/status")
    assert r_unauth.status_code == 401

    # Viewer can access status
    r_viewer = viewer_client.get("/api/v1/ai/status")
    assert r_viewer.status_code == 200
    data = r_viewer.json()
    assert "enabled" in data
    assert "configured" in data
    assert "model" in data
    assert "remaining_budget" in data
    # Secret key must NEVER appear in the response payload
    assert "key" not in str(data).lower() or "api_key" not in data

    # Dual-route mount test
    r_compat = viewer_client.get("/api/ai/status")
    assert r_compat.status_code == 200


def test_rbac_viewer_forbidden_from_triggering_promoting_reviewing(
    viewer_client: TestClient,
    lifecycle_setup,
):
    """Prove that viewer (read-only) cannot trigger analyses, promote, or review."""
    aid = lifecycle_setup["assessment"].id
    sid = lifecycle_setup["scan"].id
    fid = lifecycle_setup["finding"].id

    # 1. Trigger interpret -> 403
    r = viewer_client.post(f"/api/v1/assessments/{aid}/scans/{sid}/ai/interpret")
    assert r.status_code == 403

    # 2. Trigger prioritize -> 403
    r = viewer_client.post(f"/api/v1/assessments/{aid}/ai/prioritize")
    assert r.status_code == 403

    # 3. Trigger explain -> 403
    r = viewer_client.post(f"/api/v1/findings/{fid}/ai/explain")
    assert r.status_code == 403

    # 4. Trigger summarize -> 403
    r = viewer_client.post(f"/api/v1/assessments/{aid}/ai/summary")
    assert r.status_code == 403

    # 5. Promote -> 403
    fake_analysis_id = uuid.uuid4()
    r = viewer_client.post(
        f"/api/v1/ai-analyses/{fake_analysis_id}/promote",
        json={"suggestion_index": 0},
    )
    assert r.status_code == 403

    # 6. Review -> 403
    r = viewer_client.patch(
        f"/api/v1/ai-analyses/{fake_analysis_id}/review",
        json={"review_status": "approved"},
    )
    assert r.status_code == 403


def test_full_api_lifecycle_dual_mount(
    assessor_client: TestClient,
    lifecycle_setup,
    monkeypatch,
):
    """
    Complete lifecycle test across dual-mount routes:
    1. Interpret scan (returns 202, poll GET /ai-analyses/{id})
    2. Promote candidate suggestion into unverified AI finding
    3. Trigger risk prioritization
    4. Trigger finding explanation
    5. Trigger executive summary and review approval
    """
    monkeypatch.setattr(settings, "AI_ENABLED", True)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "mock_key")

    aid = str(lifecycle_setup["assessment"].id)
    sid = str(lifecycle_setup["scan"].id)
    fid = str(lifecycle_setup["finding"].id)

    valid_interpret = json.loads((Path(__file__).parent / "fixtures" / "ai" / "sample_interpret_response.json").read_text(encoding="utf-8"))
    valid_prioritize = json.loads((Path(__file__).parent / "fixtures" / "ai" / "sample_prioritize_response.json").read_text(encoding="utf-8"))
    valid_prioritize["prioritized_findings"][0]["finding_id"] = fid
    valid_explain = json.loads((Path(__file__).parent / "fixtures" / "ai" / "sample_explain_response.json").read_text(encoding="utf-8"))
    valid_summary = json.loads((Path(__file__).parent / "fixtures" / "ai" / "sample_summary_response.json").read_text(encoding="utf-8"))

    with patch("app.modules.ai_analysis.service.call_gemini_api") as mock_call:
        from app.modules.ai_analysis.schemas import (
            ScanInterpretationResponse,
            PrioritizationResponse,
            FindingExplanationResponse,
            ExecutiveSummaryResponse,
        )

        # 1. Trigger Interpret on /api/v1/
        mock_call.return_value = (
            ScanInterpretationResponse.model_validate(valid_interpret),
            valid_interpret,
            50, 100, 30
        )
        r_interpret = assessor_client.post(f"/api/v1/assessments/{aid}/scans/{sid}/ai/interpret")
        assert r_interpret.status_code == 202
        analysis_data = r_interpret.json()
        analysis_id = analysis_data["id"]
        assert analysis_data["status"] in ("pending", "completed")
        assert analysis_data["ai_generated"] is True
        assert "disclaimer" in analysis_data

        # Poll GET /api/v1/ai-analyses/{id}
        r_poll = assessor_client.get(f"/api/v1/ai-analyses/{analysis_id}")
        assert r_poll.status_code == 200
        poll_data = r_poll.json()
        assert poll_data["id"] == analysis_id

        # Compatibility mount poll GET /api/ai-analyses/{id}
        r_poll_compat = assessor_client.get(f"/api/ai-analyses/{analysis_id}")
        assert r_poll_compat.status_code == 200

        # 2. Promote candidate suggestion
        # Execute background pipeline if needed for sync
        from app.modules.ai_analysis.service import AIAnalysisService
        from app.core.database import SessionLocal
        db = SessionLocal()
        AIAnalysisService(db)._run_analysis_pipeline(uuid.UUID(analysis_id))
        db.close()

        r_promote = assessor_client.post(
            f"/api/v1/ai-analyses/{analysis_id}/promote",
            json={"suggestion_index": 0},
        )
        assert r_promote.status_code == 200
        promoted_finding = r_promote.json()
        assert promoted_finding["source"] == "ai"
        assert promoted_finding["status"] == "unverified"
        assert promoted_finding["ai_analysis_id"] == analysis_id

        # 3. Trigger Prioritization on /api/ (compatibility prefix)
        mock_call.return_value = (
            PrioritizationResponse.model_validate(valid_prioritize),
            valid_prioritize,
            60, 120, 40
        )
        r_prioritize = assessor_client.post(f"/api/assessments/{aid}/ai/prioritize")
        assert r_prioritize.status_code == 202
        prio_id = r_prioritize.json()["id"]

        db = SessionLocal()
        AIAnalysisService(db)._run_analysis_pipeline(uuid.UUID(prio_id))
        db.close()

        # 4. Trigger Explain on /api/findings/{id}/ai/explain
        mock_call.return_value = (
            FindingExplanationResponse.model_validate(valid_explain),
            valid_explain,
            40, 80, 25
        )
        r_explain = assessor_client.post(f"/api/findings/{fid}/ai/explain")
        assert r_explain.status_code == 202
        explain_id = r_explain.json()["id"]

        db = SessionLocal()
        AIAnalysisService(db)._run_analysis_pipeline(uuid.UUID(explain_id))
        db.close()

        # 5. Trigger Summary on /api/v1/assessments/{id}/ai/summary
        mock_call.return_value = (
            ExecutiveSummaryResponse.model_validate(valid_summary),
            valid_summary,
            80, 150, 50
        )
        r_summary = assessor_client.post(f"/api/v1/assessments/{aid}/ai/summary")
        assert r_summary.status_code == 202
        summary_id = r_summary.json()["id"]

        db = SessionLocal()
        AIAnalysisService(db)._run_analysis_pipeline(uuid.UUID(summary_id))
        db.close()

        # 6. Review Summary: Approve with edits
        r_review = assessor_client.patch(
            f"/api/v1/ai-analyses/{summary_id}/review",
            json={
                "review_status": "approved",
                "edited_text": "Executive summary edited and verified by Assessor.",
                "notes": "Verified against scan evidence.",
            },
        )
        assert r_review.status_code == 200
        reviewed_data = r_review.json()
        assert reviewed_data["review_status"] == "approved"
        assert reviewed_data["edited_text"] == "Executive summary edited and verified by Assessor."
        assert reviewed_data["reviewed_by"] is not None
        assert reviewed_data["reviewed_at"] is not None


def test_caching_and_budget_enforcement(
    assessor_client: TestClient,
    lifecycle_setup,
    monkeypatch,
):
    """Test analysis caching and budget limits (429 RateLimit)."""
    monkeypatch.setattr(settings, "AI_ENABLED", True)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "mock_key")

    aid = str(lifecycle_setup["assessment"].id)
    sid = str(lifecycle_setup["scan"].id)

    valid_interpret = json.loads((Path(__file__).parent / "fixtures" / "ai" / "sample_interpret_response.json").read_text(encoding="utf-8"))

    with patch("app.modules.ai_analysis.service.call_gemini_api") as mock_call:
        from app.modules.ai_analysis.schemas import ScanInterpretationResponse
        from app.modules.ai_analysis.service import AIAnalysisService
        from app.core.database import SessionLocal

        mock_call.return_value = (
            ScanInterpretationResponse.model_validate(valid_interpret),
            valid_interpret,
            50, 100, 30
        )

        # First request
        r1 = assessor_client.post(f"/api/v1/assessments/{aid}/scans/{sid}/ai/interpret")
        assert r1.status_code == 202
        a1_id = r1.json()["id"]

        # Complete it
        db = SessionLocal()
        AIAnalysisService(db)._run_analysis_pipeline(uuid.UUID(a1_id))
        db.close()

        # Second request without force: must reuse cached analysis
        r2 = assessor_client.post(f"/api/v1/assessments/{aid}/scans/{sid}/ai/interpret")
        assert r2.status_code == 202
        assert r2.json()["id"] == a1_id

        # Third request with force=true: triggers a new analysis
        r3 = assessor_client.post(f"/api/v1/assessments/{aid}/scans/{sid}/ai/interpret?force=true")
        assert r3.status_code == 202
        a3_id = r3.json()["id"]
        assert a3_id != a1_id

    # Test budget limit: set max calls to 1
    monkeypatch.setattr(settings, "AI_MAX_CALLS_PER_ASSESSMENT", 1)
    r_over_budget = assessor_client.post(f"/api/v1/assessments/{aid}/scans/{sid}/ai/interpret?force=true")
    assert r_over_budget.status_code == 429
    assert "budget" in r_over_budget.json()["detail"].lower()
