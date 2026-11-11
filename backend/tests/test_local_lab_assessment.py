"""Opt-in end-to-end checks for the local Compose security lab."""
import os
import time
import uuid
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.core.exceptions import ScopeViolationException
from app.modules.assessments import AssessmentCreate, AssessmentService
from app.modules.findings import FindingCategory
from app.modules.recon import ReconService
from app.modules.scans import ScanRunner
from app.modules.targets import TargetService
from app.modules.targets.schemas import ScopeItemCreate, TargetCreate
from app.modules.web_assessment.runners.zap_runner import ZapRunner


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_LOCAL_LAB_TESTS") != "1",
    reason="Set RUN_LOCAL_LAB_TESTS=1 to run against the local Juice Shop and ZAP services.",
)


def _wait_for_local_lab(db, target_id: uuid.UUID) -> None:
    deadline = time.monotonic() + 60
    last_error = "services are not ready"
    while time.monotonic() < deadline:
        try:
            response = httpx.get("http://juice-shop:3000/", timeout=5)
            response.raise_for_status()
            ZapRunner(db=db, target_id=target_id).check_reachability()
            return
        except (httpx.HTTPError, ConnectionError) as exc:
            last_error = str(exc)
            time.sleep(1)
    pytest.fail(f"Local Juice Shop/ZAP services were not ready: {last_error}")


def test_local_lab_scanner_and_web_assessment_workflows(client: TestClient):
    db = SessionLocal()
    try:
        target = TargetService(db).create_target(
            TargetCreate(
                name=f"Local Juice Shop {uuid.uuid4().hex[:8]}",
                base_url="http://juice-shop:3000",
                scope_items=[
                    ScopeItemCreate(
                        asset="http://juice-shop:3000/admin",
                        in_scope=False,
                        notes="Deliberate local scope boundary",
                    )
                ],
            )
        )
        assessment = AssessmentService(db).create_assessment(
            AssessmentCreate(
                name=f"Local Lab Assessment {uuid.uuid4().hex[:8]}",
                target_id=target.id,
            )
        )
        _wait_for_local_lab(db, target.id)

        runner = ScanRunner(db)
        first_nmap = runner.run(
            assessment_id=assessment.id,
            tool="nmap",
            target=target.base_url,
            options={"ports": "3000", "timing": "-T2", "service_version": True},
        )
        second_nmap = runner.run(
            assessment_id=assessment.id,
            tool="nmap",
            target=target.base_url,
            options={"ports": "3000", "timing": "-T2", "service_version": True},
        )
        dns_scan = runner.run(
            assessment_id=assessment.id,
            tool="dns",
            target=target.base_url,
        )

        assert first_nmap.status.value == second_nmap.status.value == "completed"
        assert dns_scan.status.value == "completed"
        recon = ReconService(db)
        first_assets = recon.list_assets(assessment.id, scan_id=first_nmap.id)
        second_assets = recon.list_assets(assessment.id, scan_id=second_nmap.id)
        assets = recon.list_assets(assessment.id)
        assert first_assets and second_assets
        assert len(assets) == len(first_assets) == len(second_assets)
        assert all(
            first_nmap.id in asset.scan_ids and second_nmap.id in asset.scan_ids
            for asset in assets
        )
        assert any(
            asset.type.value == "service"
            and asset.details.get("port") == 3000
            and asset.details.get("name") == "http"
            for asset in first_assets
        )
        assert recon.list_assets(assessment.id, scan_id=dns_scan.id)

        with patch("subprocess.run") as process:
            with pytest.raises(ScopeViolationException):
                runner.run(
                    assessment_id=assessment.id,
                    tool="nmap",
                    target="http://juice-shop:3000/admin",
                )
            process.assert_not_called()

        response = client.post(
            f"/api/v1/assessments/{assessment.id}/web-assessment",
            json={
                "categories": ["exposed_files", "session_management"],
                "include_zap": True,
                "zap_options": {
                    "spider_max_depth": 1,
                    "spider_duration_mins": 1,
                    "run_active_scan": False,
                },
                "options": {"delay_ms": 0, "max_requests": 40},
            },
        )
        assert response.status_code == 202
        scan_id = response.json()["id"]

        detail = client.get(
            f"/api/v1/assessments/{assessment.id}/scans/{scan_id}"
        )
        assert detail.status_code == 200
        assert detail.json()["status"] == "completed"
        assert "ZAP Alerts JSON" in detail.json()["raw_output"]

        findings_response = client.get(
            f"/api/v1/assessments/{assessment.id}/findings"
        )
        assert findings_response.status_code == 200
        findings = findings_response.json()
        exposed = [
            finding
            for finding in findings
            if finding["category"] == FindingCategory.EXPOSED_FILES.value
        ]
        ftp_listing_findings = [
            finding
            for finding in exposed
            if "Directory Listing Enabled" in finding["title"]
        ]
        assert ftp_listing_findings
        assert all(
            finding["affected_url"].endswith("/ftp")
            for finding in ftp_listing_findings
        )

        session_findings = [
            finding
            for finding in findings
            if finding["category"] == FindingCategory.SESSION_MANAGEMENT.value
        ]
        for finding in session_findings:
            finding_detail = client.get(
                f"/api/v1/assessments/{assessment.id}/findings/{finding['id']}"
            )
            assert finding_detail.status_code == 200
            evidence = finding_detail.json()["evidences"]
            assert evidence
            assert all(
                item["content"].startswith("Set-Cookie:")
                for item in evidence
            )
    finally:
        db.close()
