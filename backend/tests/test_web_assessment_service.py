import json
import uuid
from unittest.mock import patch, MagicMock
import pytest
from sqlalchemy import select
from app.core.database import SessionLocal
from app.modules.assessments import AssessmentCreate, AssessmentService
from app.modules.findings.models import Finding
from app.modules.recon import ReconService
from app.modules.scans.models import Scan, ScanStatus, ScanTool
from app.modules.targets import TargetService
from app.modules.targets.schemas import TargetCreate, ScopeItemCreate
from app.modules.audit import AuditService
from app.modules.web_assessment.parsers.zap_parser import parse_zap_alerts
from app.modules.web_assessment.runners.curl_runner import CurlRunner
from app.modules.web_assessment.service import WebAssessmentService
from app.modules.web_assessment.types import CapturedResponse
from app.modules.web_assessment.checks.exposed_files import check_exposed_file


@pytest.fixture
def db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_curl_runner_blocks_blacklisted_path_without_subprocess(db_session):
    """
    Scope enforcement: A blacklisted path (in_scope=False) must be skipped immediately,
    logged in audit trail (web_probe_rejected), and subprocess must NOT be called for it.
    """
    target_service = TargetService(db_session)
    audit_service = AuditService(db_session)

    target = target_service.create_target(
        TargetCreate(
            name=f"Scope Test Target {uuid.uuid4().hex[:6]}",
            base_url="http://localhost:3000",
            scope_items=[
                ScopeItemCreate(asset="http://localhost:3000/public", in_scope=True),
                ScopeItemCreate(asset="http://localhost:3000/admin", in_scope=False, notes="Blacklisted admin"),
            ],
        )
    )

    runner = CurlRunner(db=db_session, target_id=target.id)

    with patch("subprocess.run") as mock_subprocess:
        # Probe blacklisted path
        res, transcript = runner.probe("http://localhost:3000/admin")
        assert res is None
        assert "[SCOPE REJECTED]" in transcript
        # Subprocess was NEVER called!
        mock_subprocess.assert_not_called()

    # Verify audit log entry
    logs = audit_service.list_logs(limit=20)
    assert any(log.action == "web_probe_rejected" and "/admin" in str(log.detail) for log in logs)


def test_curl_runner_blocks_redirect_hop_to_out_of_scope_host(db_session):
    """
    Manual redirect validation: If a probe encounters a redirect (302) to an out-of-scope host,
    the redirect hop is blocked, logged in audit, and not followed.
    """
    target_service = TargetService(db_session)
    audit_service = AuditService(db_session)

    target = target_service.create_target(
        TargetCreate(
            name=f"Redirect Test Target {uuid.uuid4().hex[:6]}",
            base_url="http://localhost:3000",
        )
    )

    runner = CurlRunner(db=db_session, target_id=target.id)

    # Mock subprocess output for first hop: 302 redirecting to http://external-evil.com/stolen
    mock_hop1 = MagicMock()
    mock_hop1.stdout = (
        "HTTP/1.1 302 Found\r\n"
        "Location: http://external-evil.com/stolen\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    mock_hop1.stderr = ""
    mock_hop1.returncode = 0

    with patch("subprocess.run", return_value=mock_hop1) as mock_sub:
        res, transcript = runner.probe("http://localhost:3000/redirect", follow_redirects=True, max_hops=3)

        # First hop was executed
        assert mock_sub.call_count == 1
        # Second hop to external-evil.com was blocked by scope check!
        assert "[SCOPE REJECTED]" in transcript
        assert "external-evil.com" in transcript

    # Verify audit log recorded rejection
    logs = audit_service.list_logs(limit=20)
    assert any(log.action == "web_probe_rejected" and "external-evil.com" in str(log.detail) for log in logs)


def test_curl_runner_respects_request_cap(db_session):
    """Runner stops making requests when max_requests cap is reached."""
    target_service = TargetService(db_session)
    target = target_service.create_target(
        TargetCreate(
            name=f"Cap Test Target {uuid.uuid4().hex[:6]}",
            base_url="http://localhost:3000",
        )
    )

    runner = CurlRunner(db=db_session, target_id=target.id, max_requests=2, delay_ms=0)

    mock_proc = MagicMock()
    mock_proc.stdout = "HTTP/1.1 200 OK\r\n\r\nOK"
    mock_proc.stderr = ""
    mock_proc.returncode = 0

    with patch("subprocess.run", return_value=mock_proc) as mock_sub:
        r1, t1 = runner.probe("http://localhost:3000/1")
        r2, t2 = runner.probe("http://localhost:3000/2")
        r3, t3 = runner.probe("http://localhost:3000/3")

        assert r1 is not None
        assert r2 is not None
        assert r3 is None  # Cap reached!
        assert "[REQUEST CAP REACHED]" in t3
        assert mock_sub.call_count == 2


def test_curl_runner_rejects_nonzero_exit_without_http_response(db_session):
    target_service = TargetService(db_session)
    target = target_service.create_target(
        TargetCreate(
            name=f"Curl Failure Target {uuid.uuid4().hex[:6]}",
            base_url="http://localhost:3000",
        )
    )
    runner = CurlRunner(db=db_session, target_id=target.id, delay_ms=0)
    failed_process = MagicMock(
        stdout="",
        stderr="Could not connect",
        returncode=7,
    )

    with patch("subprocess.run", return_value=failed_process):
        response, transcript = runner.probe("http://localhost:3000/")

    assert response is None
    assert "[CURL ERROR]" in transcript
    assert "status 7" in transcript


def test_curl_runner_keeps_partial_juice_shop_ftp_listing(db_session):
    target_service = TargetService(db_session)
    target = target_service.create_target(
        TargetCreate(
            name=f"Juice Shop FTP Target {uuid.uuid4().hex[:6]}",
            base_url="http://localhost:3000",
        )
    )
    runner = CurlRunner(db=db_session, target_id=target.id, delay_ms=0)
    listing_body = (
        "<html><head><title>listing directory /ftp</title></head>"
        "<body><h1>listing directory /ftp</h1><a href=\"/ftp/1.txt\">1.txt</a></body></html>"
    )
    partial_process = MagicMock(
        stdout=(
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 11331\r\n\r\n"
            f"{listing_body}"
        ),
        stderr="curl: (18) transfer closed with 12 bytes remaining",
        returncode=18,
    )

    with patch("subprocess.run", return_value=partial_process):
        response, transcript = runner.probe(
            "http://localhost:3000/ftp",
            follow_redirects=False,
        )

    assert response is not None
    assert response.truncated is True
    assert "[CURL PARTIAL RESPONSE]" in transcript
    findings = check_exposed_file(response, baseline=None)
    assert len(findings) == 1
    assert "Directory Listing Enabled" in findings[0].title


def test_web_assessment_merges_zap_and_curl_and_dedupes_spider_assets(db_session):
    target_url = f"https://assessment-{uuid.uuid4().hex[:8]}.test"
    target = TargetService(db_session).create_target(
        TargetCreate(name=f"Web Assessment {uuid.uuid4().hex[:8]}", base_url=target_url)
    )
    assessment = AssessmentService(db_session).create_assessment(
        AssessmentCreate(name=f"Web Assessment {uuid.uuid4().hex[:8]}", target_id=target.id)
    )
    scan = Scan(
        assessment_id=assessment.id,
        tool=ScanTool.CURL,
        command="curl web-assessment",
        status=ScanStatus.PENDING,
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    root_response = CapturedResponse(
        url=target_url,
        method="GET",
        status=200,
        headers=[("Access-Control-Allow-Origin", "*")],
        raw_text="HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\n",
    )
    cookie_response = CapturedResponse(
        url=f"{target_url}/profile",
        method="GET",
        status=200,
        headers=[("Set-Cookie", "session=observed; Path=/")],
        raw_text="HTTP/1.1 200 OK\nSet-Cookie: session=observed; Path=/\n",
    )
    alerts = [
        {
            "name": "Content Security Policy (CSP) Header Not Set",
            "risk": "Medium",
            "pluginId": "10038",
            "url": f"{target_url}/",
            "evidence": "CSP absent",
        },
        {
            "name": "Content Security Policy (CSP) Header Not Set",
            "risk": "Medium",
            "pluginId": "10038",
            "url": f"{target_url}/about",
            "evidence": "CSP absent",
        },
        {
            "name": "Modern Web Application",
            "risk": "Informational",
            "pluginId": "10109",
            "url": target_url,
        },
        {
            "name": "Cookie No HttpOnly Flag",
            "risk": "Low",
            "pluginId": "10010",
            "url": f"{target_url}/login",
            "evidence": "session cookie",
        },
        {
            "name": "Cookie No HttpOnly Flag",
            "risk": "Low",
            "pluginId": "10010",
            "url": f"{target_url}/profile",
            "evidence": "session cookie",
        },
    ]
    raw_zap_json = json.dumps({"alerts": alerts})
    recursive_url = (
        f"{target_url}/assets/public/assets/public/assets/public/"
    )

    with (
        patch("app.modules.web_assessment.service.CurlRunner") as curl_runner,
        patch("app.modules.web_assessment.service.TlsRunner") as tls_runner,
        patch("app.modules.web_assessment.service.ZapRunner") as zap_runner,
    ):
        curl_runner.return_value.probe.side_effect = [
            (None, "baseline probe"),
            (root_response, "root probe"),
            (
                CapturedResponse(
                    url=f"{target_url}/login",
                    method="GET",
                    status=200,
                    headers=[("Content-Type", "text/html")],
                ),
                "login evidence probe",
            ),
            (cookie_response, "profile evidence probe"),
        ]
        tls_runner.return_value.check_tls.return_value = {
            "https_available": False,
            "raw_output": "TLS checks mocked",
        }
        zap_runner.return_value.execute_zap_assessment.return_value = (
            parse_zap_alerts({"alerts": alerts}),
            [f"{target_url}/about", f"{target_url}/about", recursive_url, f"{target_url}/api"],
            raw_zap_json,
        )

        result = WebAssessmentService(db_session).execute_web_assessment(
            scan_id=scan.id,
            categories=["security_headers"],
            include_zap=True,
            zap_options={},
            options={},
        )

    assert result.status == ScanStatus.COMPLETED
    assert "Modern Web Application" in result.raw_output

    findings = db_session.execute(
        select(Finding).where(Finding.assessment_id == assessment.id)
    ).scalars().all()
    csp_findings = [
        finding
        for finding in findings
        if finding.title == "Missing Content-Security-Policy Header"
    ]
    assert len(csp_findings) == 1
    csp_evidence = "\n".join(item.content or "" for item in csp_findings[0].evidences)
    assert "[Response Headers (CSP Missing)]" in csp_evidence
    assert "[ZAP Alert: Content Security Policy (CSP) Header Not Set]" in csp_evidence
    assert f"{target_url}/about" in csp_evidence

    session_finding = next(
        finding for finding in findings if finding.title == "[ZAP] Cookie No HttpOnly Flag"
    )
    assert session_finding.affected_url == f"{target_url}/profile"
    session_evidence = "\n".join(
        item.content or "" for item in session_finding.evidences
    )
    assert f"{target_url}/login" in session_evidence
    assert f"{target_url}/profile" in session_evidence
    assert "Set-Cookie: session=observed; Path=/" in session_evidence

    wildcard_cors = next(
        finding for finding in findings if finding.title == "Wildcard Access-Control-Allow-Origin"
    )
    assert wildcard_cors.severity.value == "low"
    assert "Access-Control-Allow-Origin: *" in wildcard_cors.evidences[0].content

    endpoint_assets = [
        asset
        for asset in ReconService(db_session).list_assets(assessment.id)
        if asset.type.value == "endpoint"
    ]
    endpoint_values = [asset.value for asset in endpoint_assets]
    assert endpoint_values.count(f"{target_url}/about") == 1
    assert f"{target_url}/api" in endpoint_values
    assert recursive_url not in endpoint_values
