import uuid
from unittest.mock import patch, MagicMock
import pytest
from app.core.database import SessionLocal
from app.modules.targets import TargetService
from app.modules.targets.schemas import TargetCreate, ScopeItemCreate
from app.modules.audit import AuditService
from app.modules.web_assessment.runners.curl_runner import CurlRunner


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

    with patch("subprocess.run", return_value=mock_proc) as mock_sub:
        r1, t1 = runner.probe("http://localhost:3000/1")
        r2, t2 = runner.probe("http://localhost:3000/2")
        r3, t3 = runner.probe("http://localhost:3000/3")

        assert r1 is not None
        assert r2 is not None
        assert r3 is None  # Cap reached!
        assert "[REQUEST CAP REACHED]" in t3
        assert mock_sub.call_count == 2
