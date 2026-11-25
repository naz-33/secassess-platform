"""Regression tests for report version/pending and finding fingerprint concurrency & DB integrity."""
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import patch

import pytest
from fastapi import BackgroundTasks
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import IntegrityError

from app.core.database import Base, SessionLocal
from app.core.exceptions import ConflictException
from app.modules.assessments import AssessmentService, AssessmentCreate
from app.modules.findings import (
    FindingService,
    FindingCreate,
    FindingSeverity,
    FindingStatus,
    EvidenceType,
)
from app.modules.findings.models import Finding
from app.modules.reporting import ReportingService, ReportGenerateRequest, ReportFormat, ReportStatus
from app.modules.reporting.models import Report
from app.modules.targets import TargetService
from app.modules.targets.schemas import TargetCreate


def _create_test_assessment(admin_user_id: uuid.UUID, prefix: str) -> uuid.UUID:
    db = SessionLocal()
    try:
        target = TargetService(db).create_target(
            TargetCreate(
                name=f"{prefix} Target {uuid.uuid4().hex[:6]}",
                base_url="http://127.0.0.1:8080",
                authorization_note="Authorized test target",
            ),
            user_id=admin_user_id,
        )
        assessment = AssessmentService(db).create_assessment(
            AssessmentCreate(
                name=f"{prefix} Assessment {uuid.uuid4().hex[:6]}",
                target_id=target.id,
            ),
            user_id=admin_user_id,
        )
        return assessment.id
    finally:
        db.close()


def test_report_unique_version_and_single_pending_db_constraints(admin_user):
    """DB constraints must reject duplicate (assessment_id, version) and multiple pending reports."""
    assessment_id = _create_test_assessment(admin_user.id, "ReportConstraint")
    db = SessionLocal()
    try:
        r1 = Report(
            assessment_id=assessment_id,
            version=1,
            format=ReportFormat.DOCX,
            status=ReportStatus.COMPLETED,
            generated_by=admin_user.id,
            snapshot_json={},
        )
        db.add(r1)
        db.commit()

        # Duplicate (assessment_id, version) must fail even when COMPLETED
        r_dup_ver = Report(
            assessment_id=assessment_id,
            version=1,
            format=ReportFormat.DOCX,
            status=ReportStatus.COMPLETED,
            generated_by=admin_user.id,
            snapshot_json={},
        )
        db.add(r_dup_ver)
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()

        # First PENDING report (v2) succeeds
        r2_pending = Report(
            assessment_id=assessment_id,
            version=2,
            format=ReportFormat.DOCX,
            status=ReportStatus.PENDING,
            generated_by=admin_user.id,
            snapshot_json={},
        )
        db.add(r2_pending)
        db.commit()

        # Second PENDING report (v3) for same assessment must fail
        r3_pending = Report(
            assessment_id=assessment_id,
            version=3,
            format=ReportFormat.DOCX,
            status=ReportStatus.PENDING,
            generated_by=admin_user.id,
            snapshot_json={},
        )
        db.add(r3_pending)
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
    finally:
        db.close()


def test_concurrent_report_generation_returns_409_conflict(client, admin_user, admin_headers):
    """Concurrent report generation requests for the same assessment must allow one and return 409 for others."""
    assessment_id = _create_test_assessment(admin_user.id, "ReportConcurrency")
    barrier = Barrier(2)

    def _request_report():
        barrier.wait(timeout=5)
        return client.post(
            f"/api/v1/assessments/{assessment_id}/reports",
            json={"format": "docx", "include_unverified_appendix": True},
            headers=admin_headers,
        )

    # Patch background pipeline so PENDING state persists across the concurrent POSTs
    with patch("app.modules.reporting.service._execute_report_background_worker"):
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(_request_report), pool.submit(_request_report)]
            responses = [f.result(timeout=10) for f in futures]

    statuses = sorted(r.status_code for r in responses)
    assert statuses == [202, 409], f"Expected [202, 409], got {statuses}"

    db = SessionLocal()
    try:
        reports = db.execute(
            select(Report).where(Report.assessment_id == assessment_id)
        ).scalars().all()
        assert len(reports) == 1
        assert reports[0].version == 1
        assert reports[0].status == ReportStatus.PENDING

        # Once completed, next request succeeds with version=2
        reports[0].status = ReportStatus.COMPLETED
        db.commit()

        svc = ReportingService(db)
        bg = BackgroundTasks()
        with patch("app.modules.reporting.service._execute_report_background_worker"):
            r2 = svc.request_report_generation(
                assessment_id=assessment_id,
                request=ReportGenerateRequest(format="docx"),
                user=admin_user,
                background_tasks=bg,
            )
        assert r2.version == 2
        assert r2.status == ReportStatus.PENDING.value
    finally:
        db.close()


def test_concurrent_create_finding_deduplicates_without_multiple_results_found(admin_user):
    """Concurrent create_finding calls with the same fingerprint must produce exactly one Finding."""
    assessment_id = _create_test_assessment(admin_user.id, "FindingCreateConcurrency")
    workers = 4
    barrier = Barrier(workers)

    def _create_worker():
        db = SessionLocal()
        try:
            svc = FindingService(db)
            barrier.wait(timeout=5)
            return svc.create_finding(
                FindingCreate(
                    assessment_id=assessment_id,
                    title="Missing Content-Security-Policy",
                    category="security_headers",
                    description="CSP header is missing.",
                    severity=FindingSeverity.MEDIUM,
                    affected_url="http://127.0.0.1:8080/login",
                )
            )
        finally:
            db.close()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = [f.result(timeout=10) for f in [pool.submit(_create_worker) for _ in range(workers)]]

    returned_ids = {r.id for r in results}
    assert len(returned_ids) == 1

    db = SessionLocal()
    try:
        rows = db.execute(
            select(Finding).where(Finding.assessment_id == assessment_id)
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].id == results[0].id
        # Must not raise MultipleResultsFound
        fetched = FindingService(db).repository.get_by_fingerprint(assessment_id, rows[0].fingerprint)
        assert fetched is not None and fetched.id == rows[0].id
    finally:
        db.close()


def test_concurrent_ingest_candidate_preserves_verified_status_and_severity(admin_user):
    """Concurrent ingest_candidate calls must return the existing finding without resetting status or severity."""
    assessment_id = _create_test_assessment(admin_user.id, "FindingIngestConcurrency")

    db = SessionLocal()
    try:
        svc = FindingService(db)
        initial = svc.create_finding(
            FindingCreate(
                assessment_id=assessment_id,
                title="Exposed .env File",
                category="exposed_files",
                description="Environment file exposed.",
                severity=FindingSeverity.LOW,
                affected_url="http://127.0.0.1:8080/.env",
            )
        )
        # Simulate Phase 4 verification + severity override
        row = db.execute(select(Finding).where(Finding.id == initial.id)).scalar_one()
        row.status = FindingStatus.CONFIRMED
        row.final_severity = FindingSeverity.CRITICAL
        row.severity_justification = "Confirmed secrets exposure in .env"
        row.verified_by = admin_user.id
        db.commit()
    finally:
        db.close()

    workers = 4
    barrier = Barrier(workers)

    def _ingest_worker(idx: int):
        session = SessionLocal()
        try:
            service = FindingService(session)
            barrier.wait(timeout=5)
            return service.ingest_candidate(
                assessment_id=assessment_id,
                title="Exposed .env File",
                category="exposed_files",
                description="Environment file exposed.",
                severity=FindingSeverity.MEDIUM,
                affected_url="http://127.0.0.1:8080/.env",
                evidence_content=f"GET /.env -> 200 OK (worker {idx})",
                evidence_type=EvidenceType.REQUEST_RESPONSE,
            )
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = [f.result(timeout=10) for f in [pool.submit(_ingest_worker, i) for i in range(workers)]]

    assert {r.id for r in results} == {initial.id}

    db = SessionLocal()
    try:
        rows = db.execute(
            select(Finding).where(Finding.assessment_id == assessment_id)
        ).scalars().all()
        assert len(rows) == 1
        finding = rows[0]
        assert finding.status == FindingStatus.CONFIRMED
        assert finding.original_severity == FindingSeverity.LOW
        assert finding.final_severity == FindingSeverity.CRITICAL
        assert len(finding.evidences) == workers
    finally:
        db.close()


def test_sqlite_dialect_partial_unique_indexes():
    """Verify sqlite_where partial unique indexes and unique constraints enforce identical rules on SQLite."""
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE assessments (id CHAR(32) PRIMARY KEY)"))
        conn.execute(text("CREATE TABLE users (id CHAR(32) PRIMARY KEY)"))
        conn.execute(text("CREATE TABLE scans (id CHAR(32) PRIMARY KEY)"))
        conn.execute(text("CREATE TABLE ai_analyses (id CHAR(32) PRIMARY KEY)"))
    Base.metadata.create_all(engine, tables=[Report.__table__, Finding.__table__])

    assessment_id = uuid.uuid4()
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO assessments (id) VALUES (:id)"), {"id": assessment_id.hex})

    from sqlalchemy.orm import sessionmaker

    SqliteSession = sessionmaker(bind=engine)
    db = SqliteSession()
    try:
        # Reports: duplicate (assessment_id, version) rejected
        db.add(Report(assessment_id=assessment_id, version=1, status=ReportStatus.COMPLETED, snapshot_json={}))
        db.commit()
        db.add(Report(assessment_id=assessment_id, version=1, status=ReportStatus.COMPLETED, snapshot_json={}))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()

        # Reports: multiple PENDING rejected
        db.add(Report(assessment_id=assessment_id, version=2, status=ReportStatus.PENDING, snapshot_json={}))
        db.commit()
        db.add(Report(assessment_id=assessment_id, version=3, status=ReportStatus.PENDING, snapshot_json={}))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()

        # Findings: duplicate non-null fingerprint rejected, NULL fingerprints allowed
        db.add(
            Finding(
                assessment_id=assessment_id,
                title="F1",
                category="other",
                description="d",
                severity=FindingSeverity.LOW,
                original_severity=FindingSeverity.LOW,
                fingerprint="abc123",
            )
        )
        db.commit()
        db.add(
            Finding(
                assessment_id=assessment_id,
                title="F1 dup",
                category="other",
                description="d",
                severity=FindingSeverity.LOW,
                original_severity=FindingSeverity.LOW,
                fingerprint="abc123",
            )
        )
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()

        db.add(
            Finding(
                assessment_id=assessment_id,
                title="Null FP 1",
                category="other",
                description="d",
                severity=FindingSeverity.LOW,
                original_severity=FindingSeverity.LOW,
                fingerprint=None,
            )
        )
        db.add(
            Finding(
                assessment_id=assessment_id,
                title="Null FP 2",
                category="other",
                description="d",
                severity=FindingSeverity.LOW,
                original_severity=FindingSeverity.LOW,
                fingerprint=None,
            )
        )
        db.commit()
    finally:
        db.close()
        engine.dispose()
