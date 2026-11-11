import io
import uuid
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

VALID_PNG_BYTES = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"


def test_phase4_full_lifecycle_dual_mounts(
    admin_client: TestClient,
    unauth_client: TestClient,
):
    """
    Complete end-to-end user and assessor lifecycle tested through both route prefixes
    (/api/v1/... and /api/...):
    1. Admin creates Assessor user.
    2. Assessor logs in and receives JWT access token.
    3. Assessor creates target and assessment cycle.
    4. Assessor triggers web assessment (mocking curl execution).
    5. Assessor lists unverified findings.
    6. Assessor uploads manual screenshot evidence.
    7. Assessor confirms finding (evidence_reviewed=True).
    8. Assessor overrides severity with justification.
    9. Assessor inspects verification and severity change history.
    10. Assessor views summary metrics.
    11. Admin verifies complete audit trail.
    """
    assessor_email = f"lifecycle_{uuid.uuid4().hex[:6]}@secassess.local"
    assessor_password = "AssessorPassword123!"

    # 1. Admin creates Assessor under /api/v1/users
    u_res = admin_client.post(
        "/api/v1/users",
        json={
            "name": "Lifecycle Assessor",
            "email": assessor_email,
            "password": assessor_password,
            "role": "assessor",
        },
    )
    assert u_res.status_code == 201

    # 2. Assessor logs in under /api/auth/login (compat mount)
    login_res = unauth_client.post(
        "/api/auth/login",
        json={"email": assessor_email, "password": assessor_password},
    )
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Verify profile under /api/auth/me
    me_res = unauth_client.get("/api/auth/me", headers=headers)
    assert me_res.status_code == 200
    assert me_res.json()["email"] == assessor_email

    # 3. Create target under /api/v1/targets/
    target_res = unauth_client.post(
        "/api/v1/targets/",
        headers=headers,
        json={
            "name": f"Lifecycle Target {uuid.uuid4().hex[:6]}",
            "base_url": "http://localhost:3000",
            "scope_items": [{"asset": "http://localhost:3000/", "in_scope": True}],
        },
    )
    assert target_res.status_code == 201
    target_id = target_res.json()["id"]

    # Create assessment under /api/assessments/ (compat mount)
    ass_res = unauth_client.post(
        "/api/assessments/",
        headers=headers,
        json={"name": "Lifecycle Assessment", "target_id": target_id},
    )
    assert ass_res.status_code == 201
    assessment_id = ass_res.json()["id"]

    # 4. Trigger Web Assessment under /api/v1/assessments/{id}/web-assessment (mocking curl subprocess)
    mock_response = (
        "HTTP/1.1 200 OK\r\n"
        "Server: Apache/2.4.41\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<html><body>Lifecycle Test App</body></html>"
    )
    mock_curl = MagicMock()
    mock_curl.stdout = mock_response
    mock_curl.stderr = ""
    mock_curl.returncode = 0

    with (
        patch("subprocess.run", return_value=mock_curl),
        patch(
            "app.modules.web_assessment.service.TlsRunner.check_tls",
            return_value={"https_available": False, "raw_output": "TLS probe mocked"},
        ),
    ):
        scan_res = unauth_client.post(
            f"/api/v1/assessments/{assessment_id}/web-assessment",
            headers=headers,
            json={
                "target_url": "http://localhost:3000/",
                "categories": ["security_headers"],
            },
        )
        assert scan_res.status_code == 202

    # 5. List findings under /api/assessments/{id}/findings (compat mount)
    findings_res = unauth_client.get(
        f"/api/assessments/{assessment_id}/findings",
        headers=headers,
    )
    assert findings_res.status_code == 200
    findings = findings_res.json()
    assert len(findings) > 0
    target_finding = findings[0]
    finding_id = target_finding["id"]
    assert target_finding["status"] == "unverified"
    assert target_finding["original_severity"] == target_finding["severity"]

    # 6. Upload manual evidence screenshot under /api/v1/findings/{id}/evidence/upload
    files = {"file": ("repro.png", io.BytesIO(VALID_PNG_BYTES), "image/png")}
    upload_res = unauth_client.post(
        f"/api/v1/findings/{finding_id}/evidence/upload",
        headers=headers,
        files=files,
        data={"label": "Assessor Manual Reproduction", "notes": "Confirmed reproduction"},
    )
    assert upload_res.status_code == 201
    evidence_id = upload_res.json()["id"]
    assert evidence_id

    # 7. Assessor confirms finding under /api/findings/{id}/verify (compat mount)
    verify_res = unauth_client.post(
        f"/api/findings/{finding_id}/verify",
        headers=headers,
        json={
            "decision": "confirmed",
            "evidence_reviewed": True,
            "notes": "Verified vulnerability is active and exploitable in current target scope.",
        },
    )
    assert verify_res.status_code == 201
    assert verify_res.json()["decision"] == "confirmed"

    # 8. Assessor overrides severity under /api/v1/findings/{id}/severity
    sev_res = unauth_client.patch(
        f"/api/v1/findings/{finding_id}/severity",
        headers=headers,
        json={
            "severity": "critical",
            "justification": "Elevating finding severity due to critical data exposure.",
            "cvss_score": 9.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
    )
    assert sev_res.status_code == 200
    assert sev_res.json()["final_severity"] == "critical"
    assert sev_res.json()["effective_severity"] == "critical"

    # 9. View history
    verif_hist = unauth_client.get(f"/api/findings/{finding_id}/verifications", headers=headers)
    assert verif_hist.status_code == 200
    assert len(verif_hist.json()) == 1

    sev_hist = unauth_client.get(f"/api/findings/{finding_id}/severity-history", headers=headers)
    assert sev_hist.status_code == 200
    assert len(sev_hist.json()) == 1

    # 10. Summary verification
    sum_res = unauth_client.get(f"/api/v1/assessments/{assessment_id}/findings/summary", headers=headers)
    assert sum_res.status_code == 200
    summary = sum_res.json()
    assert summary["by_status"]["confirmed"] >= 1
    assert summary["confirmed_by_effective_severity"]["critical"] >= 1
    assert summary["verified_count"] >= 1

    # 11. Admin checks audit log
    audit_res = admin_client.get("/api/v1/audit-log?limit=50")
    assert audit_res.status_code == 200
    audit_actions = [e["action"] for e in audit_res.json()]
    assert "verification_recorded" in audit_actions
    assert "severity_overridden" in audit_actions
    assert "evidence_uploaded" in audit_actions
