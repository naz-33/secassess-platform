import subprocess
import uuid
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.core.exceptions import ScopeViolationException
from app.modules.assessments import AssessmentService, AssessmentCreate
from app.modules.audit.repository import AuditRepository
from app.modules.recon import ReconService
from app.modules.scans import ScanRunner
from app.modules.scans.models import ScanStatus
from app.modules.targets import TargetService
from app.modules.targets.schemas import TargetCreate, ScopeItemCreate

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def db_session():
    """Yield a database session and clean up after test."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def target_and_assessment(db_session: Session):
    """Fixture providing a target with defined scope and an assessment."""
    target_svc = TargetService(db_session)
    target = target_svc.create_target(
        TargetCreate(
            name=f"Runner Target {uuid.uuid4().hex[:6]}",
            base_url="http://localhost:3000",
            description="Testing scan runner",
            scope_items=[
                ScopeItemCreate(asset="http://localhost:3000/api", in_scope=True),
                ScopeItemCreate(asset="http://localhost:3000/admin", in_scope=False),
            ],
        )
    )

    assessment_svc = AssessmentService(db_session)
    assessment = assessment_svc.create_assessment(
        AssessmentCreate(
            name="Runner Assessment",
            target_id=target.id,
        )
    )
    return target, assessment


def test_scan_runner_scope_rejection_never_calls_subprocess(
    db_session: Session,
    target_and_assessment,
):
    """
    Scope enforcement: scanning an out-of-scope host is rejected,
    creates a rejected scan row and an audit_log entry, and subprocess is never called.
    """
    target, assessment = target_and_assessment
    runner = ScanRunner(db_session)

    with patch("subprocess.run") as mock_subprocess:
        with pytest.raises(ScopeViolationException):
            runner.run(
                assessment_id=assessment.id,
                tool="nmap",
                target="http://evil-external-host.com",
            )

        # Subprocess must never have been called
        mock_subprocess.assert_not_called()

    # Verify scan row was created with status rejected
    scans = runner.repository.list_by_assessment(assessment.id)
    assert len(scans) >= 1
    rejected_scan = next(s for s in scans if s.status == ScanStatus.REJECTED)
    assert "Scope violation" in (rejected_scan.error or "")

    # Verify audit log recorded scan_rejected
    audit_repo = AuditRepository(db_session)
    logs = audit_repo.list_entries(limit=10)
    assert any(log.action == "scan_rejected" for log in logs)


def test_scan_runner_blacklisted_path_rejection(
    db_session: Session,
    target_and_assessment,
):
    """Verify blacklisted path (in_scope=False) is rejected even when base_url matches."""
    target, assessment = target_and_assessment
    runner = ScanRunner(db_session)

    with patch("subprocess.run") as mock_subprocess:
        with pytest.raises(ScopeViolationException):
            runner.run(
                assessment_id=assessment.id,
                tool="nmap",
                target="http://localhost:3000/admin",
            )
        mock_subprocess.assert_not_called()

    scans = runner.repository.list_by_assessment(assessment.id)
    assert any(s.status == ScanStatus.REJECTED for s in scans)


def test_scan_runner_success_path_stores_unchanged_raw_output_and_assets(
    db_session: Session,
    target_and_assessment,
):
    """
    Success path: status completed, raw_output stored UNCHANGED, assets created,
    audit logs recorded.
    """
    target, assessment = target_and_assessment
    xml_content = (FIXTURES_DIR / "nmap_open_ports.xml").read_text(encoding="utf-8")

    mock_proc = MagicMock()
    mock_proc.stdout = xml_content
    mock_proc.stderr = ""

    runner = ScanRunner(db_session)

    with patch("subprocess.run", return_value=mock_proc) as mock_subprocess:
        scan = runner.run(
            assessment_id=assessment.id,
            tool="nmap",
            target="http://localhost:3000",
            options={"top_ports": 20, "timing": "-T3"},
        )
        assert mock_subprocess.called
        assert mock_subprocess.call_args[1]["shell"] is False

    assert scan.status == ScanStatus.COMPLETED
    assert scan.started_at is not None
    assert scan.finished_at is not None
    # Raw output must be stored UNCHANGED
    assert scan.raw_output == xml_content

    # Assets must be created in database
    recon_svc = ReconService(db_session)
    assets = recon_svc.list_assets(assessment.id, scan_id=scan.id)
    assert len(assets) >= 4
    types = {a.type.value for a in assets}
    assert "host" in types
    assert "port" in types
    assert "service" in types

    # Audit logs must contain start and completion
    audit_repo = AuditRepository(db_session)
    logs = audit_repo.list_entries(limit=10)
    assert any(log.action == "scan_started" for log in logs)
    assert any(log.action == "scan_completed" for log in logs)


def test_scan_runner_subprocess_timeout(
    db_session: Session,
    target_and_assessment,
):
    """Timeout path: status failed with clear error message."""
    target, assessment = target_and_assessment
    runner = ScanRunner(db_session)

    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["nmap"], timeout=10, output="partial")):
        scan = runner.run(
            assessment_id=assessment.id,
            tool="nmap",
            target="http://localhost:3000",
        )

    assert scan.status == ScanStatus.FAILED
    assert "timed out" in (scan.error or "")
    assert scan.raw_output == "partial"


def test_scan_runner_missing_executable_graceful_failure(
    db_session: Session,
    target_and_assessment,
):
    """Missing executable path: status failed gracefully with clear error message (no unhandled 500)."""
    target, assessment = target_and_assessment
    runner = ScanRunner(db_session)

    with patch("subprocess.run", side_effect=FileNotFoundError("nmap not found")):
        scan = runner.run(
            assessment_id=assessment.id,
            tool="nmap",
            target="http://localhost:3000",
        )

    assert scan.status == ScanStatus.FAILED
    assert "not found on system PATH" in (scan.error or "")


def test_scan_runner_dns_localhost_mode_completes(
    db_session: Session,
    target_and_assessment,
):
    """DNS scan queries explicit record types and stores a clear no-data notice."""
    target, assessment = target_and_assessment
    runner = ScanRunner(db_session)

    scan = runner.run(
        assessment_id=assessment.id,
        tool="dns",
        target="http://localhost:3000",
    )

    assert scan.status == ScanStatus.COMPLETED
    assert "$ dig localhost A +noall +answer" in (scan.raw_output or "")
    assert "ANY" not in (scan.raw_output or "")


def test_scan_runner_dns_stores_query_commands_answers_and_assets(
    db_session: Session,
    target_and_assessment,
):
    target, assessment = target_and_assessment
    runner = ScanRunner(db_session)
    outputs = [
        "localhost. 60 IN A 127.0.0.1\n",
        "localhost. 60 IN AAAA ::1\n",
        "",
        "",
        "",
    ]
    mock_results = [
        MagicMock(stdout=output, stderr="", returncode=0)
        for output in outputs
    ]

    with patch("subprocess.run", side_effect=mock_results) as mock_subprocess:
        scan = runner.run(
            assessment_id=assessment.id,
            tool="dns",
            target="http://localhost:3000",
        )

    assert scan.status == ScanStatus.COMPLETED
    assert "$ dig localhost A +noall +answer" in (scan.raw_output or "")
    assert "$ dig localhost AAAA +noall +answer" in (scan.raw_output or "")
    assert "No NS records returned" in (scan.raw_output or "")
    assert "No MX records returned" in (scan.raw_output or "")
    assert all(call.kwargs["shell"] is False for call in mock_subprocess.call_args_list)

    assets = ReconService(db_session).list_assets(assessment.id, scan_id=scan.id)
    assert {asset.value for asset in assets} == {"127.0.0.1", "::1"}
