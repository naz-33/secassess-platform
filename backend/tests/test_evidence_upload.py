import io
import uuid
import pytest
from fastapi.testclient import TestClient
from app.core.database import SessionLocal
from app.modules.assessments import AssessmentService, AssessmentCreate
from app.modules.findings import FindingService, FindingSeverity
from app.modules.targets import TargetService
from app.modules.targets.schemas import TargetCreate

VALID_PNG_BYTES = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"
VALID_PDF_BYTES = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"


@pytest.fixture
def finding_for_upload(assessor_user):
    db = SessionLocal()
    try:
        ts = TargetService(db)
        as_svc = AssessmentService(db)
        fs = FindingService(db)

        target = ts.create_target(
            TargetCreate(name=f"Upload Target {uuid.uuid4().hex[:6]}", base_url="http://localhost:3000")
        )
        assessment = as_svc.create_assessment(
            AssessmentCreate(name="Upload Assessment", target_id=target.id, created_by=assessor_user.id)
        )
        finding = fs.ingest_candidate(
            assessment_id=assessment.id,
            title="Finding For Upload Tests",
            category="other",
            description="Testing manual evidence uploads",
            severity=FindingSeverity.INFO,
            affected_url="http://localhost:3000/",
        )
        return finding.id
    finally:
        db.close()


def test_valid_evidence_upload_and_download(
    assessor_client: TestClient,
    finding_for_upload,
):
    """Assessor can upload a valid PNG and download it with security headers."""
    finding_id = finding_for_upload

    # 1. Upload valid PNG
    files = {"file": ("screenshot.png", io.BytesIO(VALID_PNG_BYTES), "image/png")}
    data = {"label": "Login Page Proof", "notes": "Screenshot confirming exposed panel."}

    upload_res = assessor_client.post(
        f"/api/v1/findings/{finding_id}/evidence/upload",
        files=files,
        data=data,
    )
    assert upload_res.status_code == 201, upload_res.text
    evidence = upload_res.json()
    assert evidence["type"] == "screenshot"
    assert evidence["label"] == "Login Page Proof"
    assert evidence["sha256"] is not None
    assert evidence["original_filename"] == "screenshot.png"
    evidence_id = evidence["id"]

    # 2. Download evidence
    download_res = assessor_client.get(f"/api/v1/evidence/{evidence_id}/download")
    assert download_res.status_code == 200
    assert download_res.headers.get("X-Content-Type-Options") == "nosniff"
    assert "attachment" in download_res.headers.get("Content-Disposition", "")
    assert download_res.content == VALID_PNG_BYTES


def test_magic_bytes_rejects_disguised_file_and_svg(
    assessor_client: TestClient,
    finding_for_upload,
):
    """Files disguised with fake extensions, SVG, HTML, or executables must be rejected."""
    finding_id = finding_for_upload

    # 1. Disguised executable (MZ header disguised as .png)
    fake_png = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
    res1 = assessor_client.post(
        f"/api/v1/findings/{finding_id}/evidence/upload",
        files={"file": ("fake.png", io.BytesIO(fake_png), "image/png")},
        data={"label": "Fake PNG"},
    )
    assert res1.status_code == 415

    # 2. SVG file (prohibited due to XSS risk)
    svg_data = b"<svg xmlns='http://www.w3.org/2000/svg'><circle r='10'/></svg>"
    res2 = assessor_client.post(
        f"/api/v1/findings/{finding_id}/evidence/upload",
        files={"file": ("vector.svg", io.BytesIO(svg_data), "image/svg+xml")},
        data={"label": "Vector Graphic"},
    )
    assert res2.status_code == 415

    # 3. HTML disguised as text
    html_data = b"<!DOCTYPE html><html><body><script>alert(1)</script></body></html>"
    res3 = assessor_client.post(
        f"/api/v1/findings/{finding_id}/evidence/upload",
        files={"file": ("snippet.txt", io.BytesIO(html_data), "text/plain")},
        data={"label": "HTML Snippet"},
    )
    assert res3.status_code == 415


def test_oversize_file_rejected(
    assessor_client: TestClient,
    finding_for_upload,
):
    """Files exceeding maximum upload size limit must be rejected with 413."""
    finding_id = finding_for_upload

    # Create dummy data > 5MB
    oversize = b"%PDF-" + b"0" * (6 * 1024 * 1024)
    res = assessor_client.post(
        f"/api/v1/findings/{finding_id}/evidence/upload",
        files={"file": ("huge.pdf", io.BytesIO(oversize), "application/pdf")},
        data={"label": "Oversized Report"},
    )
    assert res.status_code == 413


def test_path_traversal_filename_sanitized(
    assessor_client: TestClient,
    finding_for_upload,
):
    """Malicious filenames containing path traversal sequences must be sanitized."""
    finding_id = finding_for_upload

    traversal_name = "../../../etc/passwd.png"
    files = {"file": (traversal_name, io.BytesIO(VALID_PNG_BYTES), "image/png")}
    res = assessor_client.post(
        f"/api/v1/findings/{finding_id}/evidence/upload",
        files=files,
        data={"label": "Traversal Test"},
    )
    assert res.status_code == 201
    evidence = res.json()
    assert ".." not in evidence["original_filename"]
    assert "/" not in evidence["original_filename"]


def test_note_evidence_endpoint(
    assessor_client: TestClient,
    finding_for_upload,
):
    """Assessor can add plain text observations via /evidence/note."""
    finding_id = finding_for_upload

    res = assessor_client.post(
        f"/api/v1/findings/{finding_id}/evidence/note",
        json={"notes": "Assessor confirmed manual reproduction with curl -I.", "label": "Repro Note"},
    )
    assert res.status_code == 201
    note = res.json()
    assert note["type"] == "output"
    assert "reproduction" in note["content"]
    assert note["label"] == "Repro Note"

