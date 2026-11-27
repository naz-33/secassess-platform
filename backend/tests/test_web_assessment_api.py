import uuid
from pathlib import Path
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
import pytest

from app.modules.findings import FindingSeverity
from app.modules.web_assessment.types import CapturedResponse, CandidateFinding

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_web_assessment_api_full_lifecycle(client: TestClient):
    """
    Comprehensive end-to-end test of Web Application Security Assessment API
    across both route prefixes (/api/v1 and /api):
    - Assessment creation
    - Web assessment trigger (202 Accepted)
    - Input validation (422 on unknown categories or disallowed options)
    - Scope violation rejection (403 Forbidden)
    - Scan detail polling
    - Discovered findings listing with filters & pagination
    - Findings summary counts
    - Evidence retrieval by finding ID and evidence ID
    """
    # 1. Create Target with in-scope and out-of-scope items
    target_payload = {
        "name": f"Web Assessment Target {uuid.uuid4().hex[:6]}",
        "base_url": "http://localhost:3000",
        "description": "OWASP Juice Shop Test Target",
        "scope_items": [
            {
                "asset": "http://localhost:3000/",
                "in_scope": True,
                "notes": "Main application root",
            },
            {
                "asset": "http://localhost:3000/admin",
                "in_scope": False,
                "notes": "Blacklisted internal administration",
            },
        ],
    }
    t_res = client.post("/api/v1/targets/", json=target_payload)
    assert t_res.status_code == 201
    target_id = t_res.json()["id"]

    # 2. Create Assessment
    ass_payload = {
        "name": "Phase 3 Web Application Security Assessment",
        "target_id": target_id,
    }
    ass_res = client.post("/api/v1/assessments/", json=ass_payload)
    assert ass_res.status_code == 201
    assessment_id = ass_res.json()["id"]

    # 3. Validation: Unknown category returns 422
    bad_cat_res = client.post(
        f"/api/v1/assessments/{assessment_id}/web-assessment",
        json={"categories": ["unsupported_category_xyz"]},
    )
    assert bad_cat_res.status_code == 422

    # 4. Validation: Disallowed option returns 422
    bad_opt_res = client.post(
        f"/api/v1/assessments/{assessment_id}/web-assessment",
        json={"options": {"disallowed_flag": "--fuzz"}},
    )
    assert bad_opt_res.status_code == 422

    # 5. Trigger Web Assessment with Mocked Curl Subprocess
    raw_juiceshop = (FIXTURES_DIR / "juiceshop_response.txt").read_text(encoding="utf-8")
    mock_curl = MagicMock()
    mock_curl.stdout = raw_juiceshop
    mock_curl.stderr = ""
    mock_curl.returncode = 0

    web_request = {
        "categories": [
            "security_headers",
            "exposed_files",
            "information_disclosure",
            "session_management",
        ],
        "include_zap": True,
        "options": {
            "delay_ms": 250,
            "max_requests": 20,
        },
    }

    with (
        patch("subprocess.run", return_value=mock_curl),
        patch("app.modules.web_assessment.runners.curl_runner.time.sleep"),
        patch(
            "app.modules.web_assessment.service.TlsRunner.check_tls",
            return_value={"https_available": False, "raw_output": "TLS probe mocked"},
        ),
        patch(
            "app.modules.web_assessment.service.ZapRunner.execute_zap_assessment",
            side_effect=ConnectionError("test ZAP outage"),
        ),
    ):
        # Trigger via /api/v1/assessments/{id}/web-assessment -> 202 Accepted
        start_res = client.post(
            f"/api/v1/assessments/{assessment_id}/web-assessment",
            json=web_request,
        )
        assert start_res.status_code == 202
        scan_data = start_res.json()
        scan_id = scan_data["id"]
        assert scan_data["tool"] == "curl"

    # 6. Verify scan status and output via dual mount /api/assessments/{id}/scans/{scan_id}
    scan_detail_res = client.get(f"/api/assessments/{assessment_id}/scans/{scan_id}")
    assert scan_detail_res.status_code == 200
    scan_detail = scan_detail_res.json()
    assert scan_detail["status"] == "completed"
    assert "Web Security Assessment" in scan_detail["raw_output"]
    assert "[ROOT TARGET PROBE]" in scan_detail["raw_output"]
    assert "[ZAP TOOL FAILURE]" in scan_detail["raw_output"]
    assert "OWASP ZAP failed" in scan_detail["error"]

    # 7. List findings via /api/v1/assessments/{id}/findings
    findings_res = client.get(f"/api/v1/assessments/{assessment_id}/findings")
    assert findings_res.status_code == 200
    findings = findings_res.json()
    assert len(findings) > 0

    # Rule: All findings must be strictly unverified in Phase 3
    assert all(f["status"] == "unverified" for f in findings)
    assert all(f["source"] == "tool" for f in findings)
    assert all(f["wstg_id"] is not None for f in findings)
    assert all(f["owasp_top10"] is not None for f in findings)

    # 8. Test filters: filter by category=security_headers via dual mount /api/assessments/{id}/findings
    hdr_findings_res = client.get(f"/api/assessments/{assessment_id}/findings?category=security_headers")
    assert hdr_findings_res.status_code == 200
    hdr_findings = hdr_findings_res.json()
    assert len(hdr_findings) > 0
    assert all(f["category"] == "security_headers" for f in hdr_findings)

    # Filter by severity
    low_findings_res = client.get(f"/api/assessments/{assessment_id}/findings?severity=low")
    assert low_findings_res.status_code == 200

    # 9. Get finding detail with attached evidence via /api/v1/assessments/{id}/findings/{finding_id}
    first_finding = findings[0]
    finding_id = first_finding["id"]

    finding_detail_res = client.get(f"/api/v1/assessments/{assessment_id}/findings/{finding_id}")
    assert finding_detail_res.status_code == 200
    finding_detail = finding_detail_res.json()
    assert finding_detail["id"] == finding_id
    assert len(finding_detail["evidences"]) >= 1

    first_evidence = finding_detail["evidences"][0]
    evidence_id = first_evidence["id"]
    assert first_evidence["finding_id"] == finding_id
    assert first_evidence["type"] == "request_response"
    assert first_evidence["content"] is not None

    # 10. Get findings summary counts via /api/v1/assessments/{id}/findings/summary
    summary_res = client.get(f"/api/v1/assessments/{assessment_id}/findings/summary")
    assert summary_res.status_code == 200
    summary = summary_res.json()
    assert summary["total"] == len(findings)
    assert summary["by_status"]["unverified"] == len(findings)
    assert summary["by_status"]["confirmed"] == 0
    assert "by_severity" in summary
    assert "by_category" in summary

    # Dual route mount for summary: /api/assessments/{id}/findings/summary
    compat_summary_res = client.get(f"/api/assessments/{assessment_id}/findings/summary")
    assert compat_summary_res.status_code == 200
    assert compat_summary_res.json()["total"] == summary["total"]

    # 11. Retrieve evidence endpoints across both route prefixes
    ev_list_res = client.get(f"/api/v1/findings/{finding_id}/evidence")
    assert ev_list_res.status_code == 200
    assert len(ev_list_res.json()) >= 1

    # Dual mount for evidence list
    compat_ev_list_res = client.get(f"/api/findings/{finding_id}/evidence")
    assert compat_ev_list_res.status_code == 200

    # Individual evidence item
    ev_detail_res = client.get(f"/api/v1/evidence/{evidence_id}")
    assert ev_detail_res.status_code == 200
    assert ev_detail_res.json()["id"] == evidence_id

    # Dual mount for individual evidence item
    compat_ev_detail_res = client.get(f"/api/evidence/{evidence_id}")
    assert compat_ev_detail_res.status_code == 200
    assert compat_ev_detail_res.json()["id"] == evidence_id


def test_web_assessment_scope_rejection_returns_403(client: TestClient):
    """When target base_url is out of scope, web-assessment triggers 403 Forbidden without execution."""
    target_payload = {
        "name": f"Blocked Target {uuid.uuid4().hex[:6]}",
        "base_url": "http://restricted-external.local",
        "scope_items": [
            {
                "asset": "http://restricted-external.local",
                "in_scope": False,  # Explicitly out-of-scope
            }
        ],
    }
    t_res = client.post("/api/v1/targets/", json=target_payload)
    assert t_res.status_code == 201
    target_id = t_res.json()["id"]

    ass_res = client.post(
        "/api/v1/assessments/",
        json={"name": "Scope Block Assessment", "target_id": target_id},
    )
    assessment_id = ass_res.json()["id"]

    with patch("subprocess.run") as mock_subprocess:
        blocked_res = client.post(
            f"/api/v1/assessments/{assessment_id}/web-assessment",
            json={"categories": ["security_headers"]},
        )
        assert blocked_res.status_code == 403
        assert "OUT OF SCOPE" in blocked_res.text or "unauthorized" in blocked_res.text
        # Subprocess never executed!
        mock_subprocess.assert_not_called()


@pytest.mark.parametrize(
    ("set_cookie", "expected_finding"),
    [
        ("", False),
        ("session=observed-session-value; HttpOnly", True),
    ],
)
def test_zap_session_finding_requires_observed_set_cookie(
    client: TestClient,
    set_cookie: str,
    expected_finding: bool,
):
    target_response = client.post(
        "/api/v1/targets/",
        json={
            "name": f"ZAP Session Evidence Target {uuid.uuid4().hex[:8]}",
            "base_url": "http://localhost:3000",
        },
    )
    assert target_response.status_code == 201
    assessment_response = client.post(
        "/api/v1/assessments/",
        json={
            "name": f"ZAP Session Evidence Assessment {uuid.uuid4().hex[:8]}",
            "target_id": target_response.json()["id"],
        },
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["id"]

    evidence_headers = [("Set-Cookie", set_cookie)] if set_cookie else []
    responses = [
        (
            CapturedResponse(
                url="http://localhost:3000/notfound_baseline",
                method="GET",
                status=404,
            ),
            "baseline response",
        ),
        (
            CapturedResponse(
                url="http://localhost:3000",
                method="GET",
                status=200,
            ),
            "root response",
        ),
        (
            CapturedResponse(
                url="http://localhost:3000/",
                method="GET",
                status=200,
                headers=evidence_headers,
            ),
            "session evidence response",
        ),
    ]
    candidate = CandidateFinding(
        title="[ZAP] Session Cookie Missing HttpOnly",
        category="session_management",
        description="ZAP reported a session cookie configuration issue.",
        severity=FindingSeverity.MEDIUM,
        affected_url="http://localhost:3000/",
        evidence_label="ZAP alert evidence",
        evidence_content="unsupported alert evidence",
    )

    with (
        patch(
            "app.modules.web_assessment.service.CurlRunner.probe",
            side_effect=responses,
        ),
        patch(
            "app.modules.web_assessment.service.TlsRunner.check_tls",
            return_value={"https_available": False, "raw_output": "TLS probe mocked"},
        ),
        patch(
            "app.modules.web_assessment.service.ZapRunner.execute_zap_assessment",
            return_value=([candidate], [], '{"alerts":[]}'),
        ),
    ):
        scan_response = client.post(
            f"/api/v1/assessments/{assessment_id}/web-assessment",
            json={
                "categories": ["session_management"],
                "include_zap": True,
                "options": {"delay_ms": 250, "max_requests": 5},
            },
        )

    assert scan_response.status_code == 202
    findings_response = client.get(
        f"/api/v1/assessments/{assessment_id}/findings"
    )
    assert findings_response.status_code == 200
    session_findings = [
        finding
        for finding in findings_response.json()
        if finding["category"] == "session_management"
    ]
    assert bool(session_findings) is expected_finding
    if expected_finding:
        detail_response = client.get(
            f"/api/v1/assessments/{assessment_id}/findings/{session_findings[0]['id']}"
        )
        assert detail_response.status_code == 200
        evidence = detail_response.json()["evidences"]
        assert len(evidence) == 1
        assert "unsupported alert evidence" in evidence[0]["content"]
        assert f"Set-Cookie: {set_cookie}" in evidence[0]["content"]


@pytest.mark.parametrize(
    "invalid_options",
    [
        {"delay_ms": 0},
        {"delay_ms": -5},
        {"delay_ms": "0"},
        {"delay_ms": True},
        {"max_requests": 100000},
        {"max_requests": 0},
        {"max_requests": -5},
        {"max_requests": True},
        {"max_requests": "10"},
        {"per_request_timeout": 0},
        {"per_request_timeout": 999},
        {"per_request_timeout": False},
        {"max_body_bytes": 0},
        {"max_body_bytes": 999999999},
        {"max_body_bytes": "2000"},
        {"unknown_key": 123},
    ],
)
def test_web_assessment_rejects_unbounded_and_invalid_options(client: TestClient, invalid_options: dict):
    """Direct API callers cannot bypass web assessment option bounds or pass invalid types/keys."""
    target_res = client.post(
        "/api/v1/targets/",
        json={
            "name": f"Web Opts Target {uuid.uuid4().hex[:6]}",
            "base_url": "http://localhost:3000",
        },
    )
    assert target_res.status_code == 201
    ass_res = client.post(
        "/api/v1/assessments/",
        json={"name": "Web Opts Validation", "target_id": target_res.json()["id"]},
    )
    assert ass_res.status_code == 201
    assessment_id = ass_res.json()["id"]

    res = client.post(
        f"/api/v1/assessments/{assessment_id}/web-assessment",
        json={"options": invalid_options},
    )
    assert res.status_code == 422


def test_web_assessment_passes_timeout_and_body_bytes_to_curl_runner(client: TestClient):
    """Valid conservative per_request_timeout and max_body_bytes reach CurlRunner and curl argv."""
    target_res = client.post(
        "/api/v1/targets/",
        json={
            "name": f"Web Runner Opts Target {uuid.uuid4().hex[:6]}",
            "base_url": "http://localhost:3000",
        },
    )
    assert target_res.status_code == 201
    ass_res = client.post(
        "/api/v1/assessments/",
        json={"name": "Web Runner Opts", "target_id": target_res.json()["id"]},
    )
    assert ass_res.status_code == 201
    assessment_id = ass_res.json()["id"]

    mock_proc = MagicMock()
    mock_proc.stdout = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"
    mock_proc.stderr = ""
    mock_proc.returncode = 0

    with (
        patch("subprocess.run", return_value=mock_proc) as mock_sub,
        patch("app.modules.web_assessment.runners.curl_runner.time.sleep"),
        patch(
            "app.modules.web_assessment.service.TlsRunner.check_tls",
            return_value={"https_available": False, "raw_output": "TLS probe mocked"},
        ),
    ):
        res = client.post(
            f"/api/v1/assessments/{assessment_id}/web-assessment",
            json={
                "categories": ["security_headers"],
                "options": {
                    "delay_ms": 300,
                    "max_requests": 5,
                    "per_request_timeout": 4,
                    "max_body_bytes": 1024,
                },
            },
        )
        assert res.status_code == 202

    assert mock_sub.called
    cmd = mock_sub.call_args_list[0].args[0]
    assert "--max-time" in cmd
    assert cmd[cmd.index("--max-time") + 1] == "4"
    assert "--max-filesize" in cmd
    assert cmd[cmd.index("--max-filesize") + 1] == "1024"
    assert mock_sub.call_args_list[0].kwargs["timeout"] == 9


def test_nmap_scan_endpoint_rejects_unbounded_custom_ports_and_accepts_valid_list(client: TestClient):
    """Direct API calls to POST /assessments/{id}/scans enforce Nmap custom port bounds."""
    target_res = client.post(
        "/api/v1/targets/",
        json={
            "name": f"Nmap API Target {uuid.uuid4().hex[:6]}",
            "base_url": "http://127.0.0.1:3000",
        },
    )
    assert target_res.status_code == 201
    ass_res = client.post(
        "/api/v1/assessments/",
        json={"name": "Nmap API Validation", "target_id": target_res.json()["id"]},
    )
    assert ass_res.status_code == 201
    assessment_id = ass_res.json()["id"]

    for bad_ports in ["1-65535", "0-99999999", "1-500,501-1001"]:
        bad_res = client.post(
            f"/api/v1/assessments/{assessment_id}/scans",
            json={"tool": "nmap", "options": {"ports": bad_ports}},
        )
        assert bad_res.status_code == 422

    mock_nmap_proc = MagicMock(
        stdout="<nmaprun><host><status state='up'/></host></nmaprun>",
        stderr="",
        returncode=0,
    )
    with patch("subprocess.run", return_value=mock_nmap_proc):
        ok_res = client.post(
            f"/api/v1/assessments/{assessment_id}/scans",
            json={"tool": "nmap", "options": {"ports": "80,80,443"}},
        )
        assert ok_res.status_code == 202


def test_web_assessment_background_worker_persists_after_request_session_closes(client: TestClient):
    """
    Regression test: POST /web-assessment must schedule the top-level worker with primitive
    args so background execution uses an isolated SessionLocal() after the request session closes,
    persisting completed scan status and findings.
    """
    from app.core.database import SessionLocal
    from app.modules.web_assessment.service import _run_web_assessment_background_worker

    target_res = client.post(
        "/api/v1/targets/",
        json={
            "name": f"BG Session Target {uuid.uuid4().hex[:6]}",
            "base_url": "http://localhost:3000",
        },
    )
    assert target_res.status_code == 201
    ass_res = client.post(
        "/api/v1/assessments/",
        json={"name": "BG Session Assessment", "target_id": target_res.json()["id"]},
    )
    assert ass_res.status_code == 201
    assessment_id = ass_res.json()["id"]

    raw_juiceshop = (FIXTURES_DIR / "juiceshop_response.txt").read_text(encoding="utf-8")
    mock_curl = MagicMock(stdout=raw_juiceshop, stderr="", returncode=0)

    with (
        patch("subprocess.run", return_value=mock_curl),
        patch("app.modules.web_assessment.runners.curl_runner.time.sleep"),
        patch(
            "app.modules.web_assessment.service.TlsRunner.check_tls",
            return_value={"https_available": False, "raw_output": "TLS probe mocked"},
        ),
        patch(
            "app.modules.web_assessment.service._run_web_assessment_background_worker",
            wraps=_run_web_assessment_background_worker,
        ) as spy_worker,
    ):
        res = client.post(
            f"/api/v1/assessments/{assessment_id}/web-assessment",
            json={"categories": ["security_headers"], "include_zap": False},
        )
        assert res.status_code == 202
        scan_id = res.json()["id"]

        assert spy_worker.call_count == 1
        worker_args = spy_worker.call_args.args
        assert worker_args[0] == uuid.UUID(assessment_id)
        assert worker_args[1] == uuid.UUID(scan_id)
        assert isinstance(worker_args[2], dict)
        assert worker_args[2]["categories"] == ["security_headers"]

    # Verify persisted scan status and findings in a fresh session
    scan_res = client.get(f"/api/v1/assessments/{assessment_id}/scans/{scan_id}")
    assert scan_res.status_code == 200
    assert scan_res.json()["status"] == "completed"

    findings_res = client.get(f"/api/v1/assessments/{assessment_id}/findings")
    assert findings_res.status_code == 200
    assert len(findings_res.json()) > 0

    # Also verify worker failure handling marks scan failed and writes audit log
    with patch(
        "app.modules.web_assessment.service.WebAssessmentService.execute_web_assessment",
        side_effect=RuntimeError("simulated worker crash"),
    ):
        fail_res = client.post(
            f"/api/v1/assessments/{assessment_id}/web-assessment",
            json={"categories": ["security_headers"], "include_zap": False},
        )
        assert fail_res.status_code == 202
        failed_scan_id = fail_res.json()["id"]

    failed_scan_res = client.get(f"/api/v1/assessments/{assessment_id}/scans/{failed_scan_id}")
    assert failed_scan_res.status_code == 200
    assert failed_scan_res.json()["status"] == "failed"
    assert "simulated worker crash" in failed_scan_res.json()["error"]

    from app.modules.audit import AuditService

    db = SessionLocal()
    try:
        logs = AuditService(db).list_logs(limit=20)
        assert any(
            log.action == "web_assessment_failed"
            and failed_scan_id in str(log.detail)
            and "simulated worker crash" in str(log.detail)
            for log in logs
        )
    finally:
        db.close()
