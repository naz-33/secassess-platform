import uuid
from pathlib import Path
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_assessments_and_scans_api_lifecycle(client: TestClient):
    """
    Comprehensive test of Assessment and Scan lifecycle across both route prefixes
    (/api/v1/assessments and /api/assessments).
    """
    # 1. Create a Target with explicit Scope Items
    target_payload = {
        "name": f"API Assessment Target {uuid.uuid4().hex[:6]}",
        "base_url": "http://localhost:3000",
        "description": "Target for automated API assessment tests",
        "scope_items": [
            {
                "asset": "http://localhost:3000/api",
                "in_scope": True,
                "notes": "Allowed API routes",
            },
            {
                "asset": "http://localhost:3000/admin",
                "in_scope": False,
                "notes": "Restricted admin portal",
            },
        ],
    }
    create_target_res = client.post("/api/v1/targets/", json=target_payload)
    assert create_target_res.status_code == 201
    target_id = create_target_res.json()["id"]

    # 2. Create Assessment via /api/v1/assessments/
    assessment_payload = {
        "name": "Phase 2 Security Recon Assessment",
        "target_id": target_id,
    }
    create_ass_res = client.post("/api/v1/assessments/", json=assessment_payload)
    assert create_ass_res.status_code == 201
    assessment = create_ass_res.json()
    assessment_id = assessment["id"]
    assert assessment["name"] == assessment_payload["name"]
    assert assessment["target_id"] == target_id
    assert assessment["status"] == "draft"

    # 3. Verify dual-mount compatibility (/api/assessments/)
    compat_res = client.get("/api/assessments/")
    assert compat_res.status_code == 200
    assert any(a["id"] == assessment_id for a in compat_res.json())

    # 4. Read Assessment by ID via /api/v1/
    get_ass_res = client.get(f"/api/v1/assessments/{assessment_id}")
    assert get_ass_res.status_code == 200
    assert get_ass_res.json()["id"] == assessment_id

    # 5. Non-existent Assessment returns 404
    non_existent_id = str(uuid.uuid4())
    assert client.get(f"/api/v1/assessments/{non_existent_id}").status_code == 404

    # 6. Trigger Nmap Scan with Mocked Process
    xml_content = (FIXTURES_DIR / "nmap_open_ports.xml").read_text(encoding="utf-8")
    mock_proc = MagicMock()
    mock_proc.stdout = xml_content
    mock_proc.stderr = ""
    mock_proc.returncode = 0

    scan_payload = {
        "tool": "nmap",
        "target": "http://localhost:3000/api",
        "options": {
            "top_ports": 50,
            "timing": "-T3",
            "service_version": True,
        },
    }

    with patch("subprocess.run", return_value=mock_proc):
        # Trigger scan -> 202 Accepted
        scan_res = client.post(
            f"/api/v1/assessments/{assessment_id}/scans",
            json=scan_payload,
        )
        assert scan_res.status_code == 202
        scan_data = scan_res.json()
        scan_id = scan_data["id"]
        assert scan_data["tool"] == "nmap"

    # 7. List scans for assessment via dual mount /api/assessments/{id}/scans
    list_scans_res = client.get(f"/api/assessments/{assessment_id}/scans")
    assert list_scans_res.status_code == 200
    scans_list = list_scans_res.json()
    assert len(scans_list) >= 1
    assert any(s["id"] == scan_id for s in scans_list)

    # 8. Get scan detail (includes status, raw_output)
    scan_detail_res = client.get(f"/api/v1/assessments/{assessment_id}/scans/{scan_id}")
    assert scan_detail_res.status_code == 200
    scan_detail = scan_detail_res.json()
    assert scan_detail["id"] == scan_id
    assert scan_detail["status"] == "completed"
    assert scan_detail["raw_output"] == xml_content

    # 9. List discovered assets via /api/v1/assessments/{id}/assets
    assets_res = client.get(f"/api/v1/assessments/{assessment_id}/assets")
    assert assets_res.status_code == 200
    assets = assets_res.json()
    assert len(assets) >= 4

    # Filter by type=port
    port_assets_res = client.get(f"/api/v1/assessments/{assessment_id}/assets?type=port")
    assert port_assets_res.status_code == 200
    port_assets = port_assets_res.json()
    assert len(port_assets) >= 2
    assert all(a["type"] == "port" for a in port_assets)

    # Filter by scan_id
    scan_filtered_res = client.get(f"/api/assessments/{assessment_id}/assets?scan_id={scan_id}")
    assert scan_filtered_res.status_code == 200
    assert len(scan_filtered_res.json()) >= 4

    # 10. Trigger DNS Scan on localhost (queries explicit record types)
    dns_payload = {
        "tool": "dns",
        "target": "http://localhost:3000",
    }
    with patch(
        "subprocess.run",
        side_effect=[
            MagicMock(stdout="", stderr="", returncode=0)
            for _ in range(5)
        ],
    ):
        dns_res = client.post(
            f"/api/v1/assessments/{assessment_id}/scans",
            json=dns_payload,
        )
    assert dns_res.status_code == 202
    dns_scan_id = dns_res.json()["id"]

    dns_detail_res = client.get(f"/api/v1/assessments/{assessment_id}/scans/{dns_scan_id}")
    assert dns_detail_res.status_code == 200
    assert dns_detail_res.json()["status"] == "completed"
    assert "$ dig localhost A +noall +answer" in (dns_detail_res.json()["raw_output"] or "")
    assert "ANY" not in (dns_detail_res.json()["raw_output"] or "")

    # 11. Scope Rejection returns 403 Forbidden
    out_of_scope_payload = {
        "tool": "nmap",
        "target": "http://localhost:3000/admin",  # explicitly marked in_scope=False
    }
    with patch("subprocess.run") as mock_subprocess:
        blocked_res = client.post(
            f"/api/v1/assessments/{assessment_id}/scans",
            json=out_of_scope_payload,
        )
        assert blocked_res.status_code == 403
        assert "OUT OF SCOPE" in blocked_res.text or "unauthorized" in blocked_res.text
        # Subprocess never executed
        mock_subprocess.assert_not_called()

    # 12. Invalid options return 422 Unprocessable Entity
    invalid_opts_payload = {
        "tool": "nmap",
        "target": "http://localhost:3000/api",
        "options": {
            "arbitrary_flag": "-A",  # disallowed option
        },
    }
    invalid_res = client.post(
        f"/api/v1/assessments/{assessment_id}/scans",
        json=invalid_opts_payload,
    )
    assert invalid_res.status_code == 422

    # 13. Invalid tool returns 422 Unprocessable Entity
    invalid_tool_payload = {
        "tool": "unsupported_tool_xyz",
    }
    tool_res = client.post(
        f"/api/v1/assessments/{assessment_id}/scans",
        json=invalid_tool_payload,
    )
    assert tool_res.status_code == 422
