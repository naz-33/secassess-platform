import uuid
from fastapi.testclient import TestClient


def test_unauthenticated_requests_get_401(unauth_client: TestClient):
    """Unauthenticated calls must receive 401 on protected endpoints across all modules."""
    fake_id = uuid.uuid4()
    protected_endpoints = [
        ("GET", "/api/v1/auth/me"),
        ("GET", "/api/v1/users"),
        ("POST", "/api/v1/users"),
        ("GET", "/api/v1/targets/"),
        ("POST", "/api/v1/targets/"),
        ("GET", f"/api/v1/targets/{fake_id}"),
        ("GET", "/api/v1/assessments/"),
        ("POST", "/api/v1/assessments/"),
        ("GET", f"/api/v1/assessments/{fake_id}"),
        ("GET", f"/api/v1/scans/{fake_id}"),
        ("GET", f"/api/v1/findings/{fake_id}"),
        ("POST", f"/api/v1/findings/{fake_id}/verify"),
        ("PATCH", f"/api/v1/findings/{fake_id}/severity"),
        ("GET", "/api/v1/audit-log"),
    ]

    for method, path in protected_endpoints:
        if method == "GET":
            res = unauth_client.get(path)
        elif method == "POST":
            res = unauth_client.post(path, json={})
        elif method == "PATCH":
            res = unauth_client.patch(path, json={})
        assert res.status_code == 401, f"Expected 401 for {method} {path}, got {res.status_code}"


def test_admin_only_endpoints_reject_assessor_and_viewer(
    assessor_client: TestClient,
    viewer_client: TestClient,
):
    """User administration and audit log inspection must strictly require admin role."""
    fake_user_id = uuid.uuid4()
    admin_routes = [
        ("GET", "/api/v1/users"),
        ("POST", "/api/v1/users"),
        ("PATCH", f"/api/v1/users/{fake_user_id}"),
        ("GET", "/api/v1/audit-log"),
    ]

    for method, path in admin_routes:
        # Assessor
        res_assessor = (
            assessor_client.get(path) if method == "GET"
            else assessor_client.post(path, json={}) if method == "POST"
            else assessor_client.patch(path, json={})
        )
        assert res_assessor.status_code == 403, f"Assessor got {res_assessor.status_code} for {path}"

        # Viewer
        res_viewer = (
            viewer_client.get(path) if method == "GET"
            else viewer_client.post(path, json={}) if method == "POST"
            else viewer_client.patch(path, json={})
        )
        assert res_viewer.status_code == 403, f"Viewer got {res_viewer.status_code} for {path}"


def test_viewer_cannot_perform_write_actions(
    viewer_client: TestClient,
    admin_client: TestClient,
):
    """Viewer role is strictly read-only and blocked from creating or modifying resources."""
    fake_id = uuid.uuid4()

    # 1. Targets
    res_target = viewer_client.post(
        "/api/v1/targets/",
        json={"name": "Forbidden Target", "base_url": "http://localhost:3000"},
    )
    assert res_target.status_code == 403

    # 2. Scope
    res_scope = viewer_client.post(
        f"/api/v1/targets/{fake_id}/scope",
        json={"asset": "http://localhost:3000/api", "in_scope": True},
    )
    assert res_scope.status_code == 403

    # 3. Assessments
    res_ass = viewer_client.post(
        "/api/v1/assessments/",
        json={"name": "Forbidden Assessment", "target_id": str(fake_id)},
    )
    assert res_ass.status_code == 403

    # 4. Scans
    res_scan = viewer_client.post(
        f"/api/v1/assessments/{fake_id}/scans",
        json={"tool": "dns", "command": "dig localhost"},
    )
    assert res_scan.status_code == 403

    # 5. Finding verification
    res_verify = viewer_client.post(
        f"/api/v1/findings/{fake_id}/verify",
        json={"decision": "confirmed", "evidence_reviewed": True},
    )
    assert res_verify.status_code == 403

    # 6. Severity override
    res_sev = viewer_client.patch(
        f"/api/v1/findings/{fake_id}/severity",
        json={"severity": "high", "justification": "Viewer trying to override"},
    )
    assert res_sev.status_code == 403


def test_viewer_can_read_endpoints(viewer_client: TestClient):
    """Viewer can read targets and assessments without 403."""
    res_targets = viewer_client.get("/api/v1/targets/")
    assert res_targets.status_code == 200

    res_assessments = viewer_client.get("/api/v1/assessments/")
    assert res_assessments.status_code == 200

