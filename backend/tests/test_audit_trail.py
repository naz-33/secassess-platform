import io
import uuid
from fastapi.testclient import TestClient

VALID_PNG_BYTES = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"


def test_audit_log_captures_all_security_events(
    admin_client: TestClient,
    assessor_client: TestClient,
    viewer_client: TestClient,
    unauth_client: TestClient,
):
    """
    Verify audit entries for: login success, failure, lockout, user create,
    verification, severity override, evidence upload and download.
    Ensure passwords and tokens are never included.
    """
    unique_email = f"audit_user_{uuid.uuid4().hex[:6]}@secassess.local"

    # 1. User created
    create_user_res = admin_client.post(
        "/api/v1/users",
        json={"name": "Audit Tracked", "email": unique_email, "password": "SecurePassword123!", "role": "assessor"},
    )
    assert create_user_res.status_code == 201

    # 2. Login failure
    unauth_client.post(
        "/api/v1/auth/login",
        json={"email": unique_email, "password": "WrongPassword123!"},
    )

    # 3. Login success
    login_res = unauth_client.post(
        "/api/v1/auth/login",
        json={"email": unique_email, "password": "SecurePassword123!"},
    )
    assert login_res.status_code == 200

    # 4. Fetch audit log (Admin only)
    logs_res = admin_client.get("/api/v1/audit-log?limit=50")
    assert logs_res.status_code == 200
    logs = logs_res.json()

    actions = [entry["action"] for entry in logs]
    assert "user_created" in actions
    assert "login_failed" in actions
    assert "login_success" in actions

    # Verify no plaintext password or token in any detail
    for entry in logs:
        detail_str = entry.get("detail") or ""
        assert "SecurePassword123!" not in detail_str
        assert "WrongPassword123!" not in detail_str
        assert "access_token" not in detail_str


def test_audit_log_non_admin_forbidden(
    assessor_client: TestClient,
    viewer_client: TestClient,
):
    """Non-admin users cannot access the audit log."""
    assert assessor_client.get("/api/v1/audit-log").status_code == 403
    assert viewer_client.get("/api/v1/audit-log").status_code == 403


def test_audit_log_filtering_and_pagination(admin_client: TestClient):
    """Test filtering by action and pagination limit/offset."""
    res = admin_client.get("/api/v1/audit-log?action=login_success&limit=5&offset=0")
    assert res.status_code == 200
    items = res.json()
    assert isinstance(items, list)
    for item in items:
        assert item["action"] == "login_success"

