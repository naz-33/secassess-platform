import hashlib
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.core.database import SessionLocal
from app.modules.assessments import AssessmentCreate, AssessmentService
from app.modules.findings import EvidenceType, FindingService, FindingSeverity
from app.modules.findings.models import Evidence
from app.modules.scans import Scan, ScanArtifact, ScanStatus, ScanTool, save_raw_artifact
from app.modules.targets import TargetService
from app.modules.targets.schemas import TargetCreate
from app.modules.web_assessment.runners.curl_runner import CurlRunner


@pytest.fixture
def db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def _create_scan(db_session, admin_user, base_url: str = "http://127.0.0.1:8000"):
    target_service = TargetService(db_session)
    assessment_service = AssessmentService(db_session)
    target = target_service.create_target(
        TargetCreate(
            name=f"Artifact Target {uuid.uuid4().hex[:6]}",
            base_url=base_url,
            scope_items=[],
        ),
        user_id=admin_user.id,
    )
    assessment = assessment_service.create_assessment(
        AssessmentCreate(
            name=f"Artifact Assessment {uuid.uuid4().hex[:6]}",
            target_id=target.id,
        ),
        user_id=admin_user.id,
    )
    scan = Scan(
        assessment_id=assessment.id,
        tool=ScanTool.CURL,
        command="curl web-assessment",
        status=ScanStatus.RUNNING,
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)
    return target, assessment, scan


def test_save_raw_artifact_preserves_bytes_and_never_overwrites(
    db_session, admin_user, tmp_path, monkeypatch
):
    monkeypatch.setattr(settings, "ARTIFACT_DIR", str(tmp_path))
    _, _, scan = _create_scan(db_session, admin_user)

    raw_stdout = b"HTTP/1.1 200 OK\r\nX-Custom: val\r\n\r\nhello\xffworld\r\n"
    raw_stderr = b"warning: minor\r\n"
    inv_id = uuid.uuid4()

    artifact = save_raw_artifact(
        db_session,
        scan_id=scan.id,
        tool="curl",
        stdout_bytes=raw_stdout,
        stderr_bytes=raw_stderr,
        command="curl -i http://127.0.0.1/",
        target_url="http://127.0.0.1/",
        exit_code=0,
        duration_ms=12.5,
        invocation_id=inv_id,
    )

    stdout_path = Path(artifact.file_path)
    stderr_path = stdout_path.with_suffix(".stderr")
    assert stdout_path.exists()
    assert stderr_path.exists()
    assert stdout_path.read_bytes() == raw_stdout
    assert stderr_path.read_bytes() == raw_stderr
    assert artifact.size_bytes == len(raw_stdout)
    assert artifact.sha256 == hashlib.sha256(raw_stdout).hexdigest()

    # Exclusive-create mode must prevent overwriting an existing artifact file
    with pytest.raises(FileExistsError):
        save_raw_artifact(
            db_session,
            scan_id=scan.id,
            tool="curl",
            stdout_bytes=b"DIFFERENT BYTES",
            invocation_id=inv_id,
        )
    assert stdout_path.read_bytes() == raw_stdout


def test_curl_runner_preserves_exact_raw_bytes_and_crlf(
    db_session, admin_user, tmp_path, monkeypatch
):
    monkeypatch.setattr(settings, "ARTIFACT_DIR", str(tmp_path))
    target, _, scan = _create_scan(db_session, admin_user, base_url="http://localhost:3000")

    raw_http = (
        b"HTTP/1.1 100 Continue\r\n\r\n"
        b"HTTP/1.1 200 OK\r\n"
        b"Server: TestServer/1.0\r\n"
        b"\r\n"
        b"Body\r\nWith\r\nCRLF\xff"
    )
    mock_proc = MagicMock(stdout=raw_http, stderr=b"", returncode=0)

    runner = CurlRunner(db=db_session, target_id=target.id, scan_id=scan.id)
    with patch("subprocess.run", return_value=mock_proc):
        captured, _ = runner.probe("http://localhost:3000/")

    assert captured is not None
    assert captured.artifact_file_path is not None
    assert captured.artifact_sha256 == hashlib.sha256(raw_http).hexdigest()
    assert Path(captured.artifact_file_path).read_bytes() == raw_http


def test_ingest_candidate_creates_companion_output_evidence_and_allows_download(
    db_session, admin_user, client, admin_token, tmp_path, monkeypatch
):
    monkeypatch.setattr(settings, "ARTIFACT_DIR", str(tmp_path))
    _, assessment, scan = _create_scan(db_session, admin_user)

    raw_bytes = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nraw payload\r\n"
    artifact = save_raw_artifact(
        db_session,
        scan_id=scan.id,
        tool="curl",
        stdout_bytes=raw_bytes,
        target_url="http://127.0.0.1:8000/",
        exit_code=0,
    )

    finding_service = FindingService(db_session)
    finding = finding_service.ingest_candidate(
        assessment_id=assessment.id,
        scan_id=scan.id,
        title="Missing X-Frame-Options",
        category="security_headers",
        description="Header missing",
        severity=FindingSeverity.LOW,
        affected_url="http://127.0.0.1:8000/",
        evidence_content="Excerpt: header absent",
        evidence_label="Header check",
        evidence_type=EvidenceType.REQUEST_RESPONSE,
        artifact_file_path=artifact.file_path,
        artifact_sha256=artifact.sha256,
    )

    evidences = list(
        db_session.execute(
            select(Evidence).where(Evidence.finding_id == finding.id)
        ).scalars().all()
    )
    assert len(evidences) == 2

    excerpt_ev = next(e for e in evidences if e.type == EvidenceType.REQUEST_RESPONSE)
    raw_ev = next(e for e in evidences if e.type == EvidenceType.OUTPUT)
    assert excerpt_ev.content == "Excerpt: header absent"
    assert raw_ev.content is None
    assert raw_ev.file_path == artifact.file_path
    assert raw_ev.sha256 == artifact.sha256
    assert raw_ev.original_filename == Path(artifact.file_path).name

    resp = client.get(
        f"/api/v1/evidence/{raw_ev.id}/download",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert resp.content == raw_bytes


def test_live_curl_probe_against_local_http_server_preserves_crlf(
    db_session, admin_user, tmp_path, monkeypatch
):
    monkeypatch.setattr(settings, "ARTIFACT_DIR", str(tmp_path))

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"hello local target\r\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{port}"
        target, _, scan = _create_scan(db_session, admin_user, base_url=base_url)

        runner = CurlRunner(db=db_session, target_id=target.id, scan_id=scan.id)
        captured, _ = runner.probe(f"{base_url}/")

        assert captured is not None
        assert captured.status == 200
        assert captured.artifact_file_path is not None

        raw_bytes = Path(captured.artifact_file_path).read_bytes()
        assert b"\r\n\r\nhello local target\r\n" in raw_bytes
        assert captured.artifact_sha256 == hashlib.sha256(raw_bytes).hexdigest()

        artifact_row = db_session.execute(
            select(ScanArtifact).where(ScanArtifact.scan_id == scan.id)
        ).scalar_one()
        assert artifact_row.sha256 == hashlib.sha256(raw_bytes).hexdigest()
        assert artifact_row.size_bytes == len(raw_bytes)
    finally:
        server.shutdown()
        server.server_close()
