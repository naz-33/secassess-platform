import json
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.database import SessionLocal
from app.modules.audit.models import AuditLog

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _create_target_and_assessment(
    client: TestClient,
    scope_items: list[dict],
) -> str:
    target_res = client.post(
        "/api/v1/targets/",
        json={
            "name": f"Audit Target {uuid.uuid4().hex[:6]}",
            "base_url": "http://localhost:3000",
            "description": "Target for scan audit attribution tests",
            "scope_items": scope_items,
        },
    )
    assert target_res.status_code == 201
    target_id = target_res.json()["id"]

    assessment_res = client.post(
        "/api/v1/assessments/",
        json={
            "name": f"Audit Assessment {uuid.uuid4().hex[:6]}",
            "target_id": target_id,
        },
    )
    assert assessment_res.status_code == 201
    return assessment_res.json()["id"]


def _get_audit_rows_for_entity(
    actions: list[str],
    *,
    scan_id: str | None = None,
    assessment_id: str | None = None,
) -> dict[str, AuditLog]:
    db = SessionLocal()
    try:
        rows = (
            db.execute(
                select(AuditLog)
                .where(AuditLog.action.in_(actions))
                .order_by(AuditLog.created_at.desc())
            )
            .scalars()
            .all()
        )
        matched: dict[str, AuditLog] = {}
        for row in rows:
            if row.action in matched or not row.detail:
                continue
            detail = json.loads(row.detail)
            if scan_id is not None and detail.get("scan_id") != scan_id:
                continue
            if assessment_id is not None and detail.get("assessment_id") != assessment_id:
                continue
            matched[row.action] = row
        return matched
    finally:
        db.close()


def test_scan_endpoint_records_user_id_for_start_completion_failure_and_rejection(
    client: TestClient,
    assessor_user,
):
    assessment_id = _create_target_and_assessment(
        client,
        scope_items=[
            {"asset": "http://localhost:3000/api", "in_scope": True},
            {"asset": "http://localhost:3000/admin", "in_scope": False},
        ],
    )

    # 1. Start + Completion
    xml_content = (FIXTURES_DIR / "nmap_open_ports.xml").read_text(encoding="utf-8")
    mock_proc = MagicMock(stdout=xml_content, stderr="", returncode=0)
    with patch("subprocess.run", return_value=mock_proc):
        res = client.post(
            f"/api/v1/assessments/{assessment_id}/scans",
            json={"tool": "nmap", "target": "http://localhost:3000/api"},
        )
    assert res.status_code == 202
    completed_scan_id = res.json()["id"]

    completed_rows = _get_audit_rows_for_entity(
        ["scan_started", "scan_completed"],
        scan_id=completed_scan_id,
    )
    assert set(completed_rows.keys()) == {"scan_started", "scan_completed"}
    assert completed_rows["scan_started"].user_id == assessor_user.id
    assert completed_rows["scan_completed"].user_id == assessor_user.id

    # 2. Start + Failure
    with patch("subprocess.run", side_effect=FileNotFoundError("nmap missing")):
        fail_res = client.post(
            f"/api/v1/assessments/{assessment_id}/scans",
            json={"tool": "nmap", "target": "http://localhost:3000/api"},
        )
    assert fail_res.status_code == 202
    failed_scan_id = fail_res.json()["id"]

    failed_rows = _get_audit_rows_for_entity(
        ["scan_started", "scan_failed"],
        scan_id=failed_scan_id,
    )
    assert set(failed_rows.keys()) == {"scan_started", "scan_failed"}
    assert failed_rows["scan_started"].user_id == assessor_user.id
    assert failed_rows["scan_failed"].user_id == assessor_user.id

    # 3. Scope Rejection
    rej_res = client.post(
        f"/api/v1/assessments/{assessment_id}/scans",
        json={"tool": "nmap", "target": "http://localhost:3000/admin"},
    )
    assert rej_res.status_code == 403

    rejected_rows = _get_audit_rows_for_entity(
        ["scan_rejected"],
        assessment_id=assessment_id,
    )
    assert "scan_rejected" in rejected_rows
    assert rejected_rows["scan_rejected"].user_id == assessor_user.id


def test_web_assessment_endpoint_records_user_id_for_start_completion_failure_and_rejection(
    client: TestClient,
    assessor_user,
):
    in_scope_assessment_id = _create_target_and_assessment(
        client,
        scope_items=[{"asset": "http://localhost:3000/", "in_scope": True}],
    )

    # 1. Start + Completion
    raw_juiceshop = (FIXTURES_DIR / "juiceshop_response.txt").read_text(encoding="utf-8")
    mock_curl = MagicMock(stdout=raw_juiceshop, stderr="", returncode=0)
    with (
        patch("subprocess.run", return_value=mock_curl),
        patch("app.modules.web_assessment.runners.curl_runner.time.sleep"),
        patch(
            "app.modules.web_assessment.service.TlsRunner.check_tls",
            return_value={"https_available": False, "raw_output": "TLS probe mocked"},
        ),
    ):
        res = client.post(
            f"/api/v1/assessments/{in_scope_assessment_id}/web-assessment",
            json={"categories": ["security_headers"], "include_zap": False},
        )
    assert res.status_code == 202
    completed_scan_id = res.json()["id"]

    completed_rows = _get_audit_rows_for_entity(
        ["web_assessment_started", "web_assessment_completed"],
        scan_id=completed_scan_id,
    )
    assert set(completed_rows.keys()) == {"web_assessment_started", "web_assessment_completed"}
    assert completed_rows["web_assessment_started"].user_id == assessor_user.id
    assert completed_rows["web_assessment_completed"].user_id == assessor_user.id

    # 2. Start + Failure
    with patch(
        "app.modules.web_assessment.service.CurlRunner.probe",
        side_effect=RuntimeError("simulated curl runner failure"),
    ):
        fail_res = client.post(
            f"/api/v1/assessments/{in_scope_assessment_id}/web-assessment",
            json={"categories": ["security_headers"], "include_zap": False},
        )
    assert fail_res.status_code == 202
    failed_scan_id = fail_res.json()["id"]

    failed_rows = _get_audit_rows_for_entity(
        ["web_assessment_started", "web_assessment_failed"],
        scan_id=failed_scan_id,
    )
    assert set(failed_rows.keys()) == {"web_assessment_started", "web_assessment_failed"}
    assert failed_rows["web_assessment_started"].user_id == assessor_user.id
    assert failed_rows["web_assessment_failed"].user_id == assessor_user.id

    # 3. Scope Rejection
    out_of_scope_assessment_id = _create_target_and_assessment(
        client,
        scope_items=[{"asset": "http://localhost:3000", "in_scope": False}],
    )
    rej_res = client.post(
        f"/api/v1/assessments/{out_of_scope_assessment_id}/web-assessment",
        json={"categories": ["security_headers"], "include_zap": False},
    )
    assert rej_res.status_code == 403

    rejected_rows = _get_audit_rows_for_entity(
        ["scan_rejected"],
        assessment_id=out_of_scope_assessment_id,
    )
    assert "scan_rejected" in rejected_rows
    assert rejected_rows["scan_rejected"].user_id == assessor_user.id
