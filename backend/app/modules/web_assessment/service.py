import datetime
import urllib.parse
import uuid
from typing import List, Dict, Any, Optional
from fastapi import BackgroundTasks
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundException, ScopeViolationException
from app.modules.assessments import AssessmentService
from app.modules.targets import TargetService
from app.modules.audit import AuditService
from app.modules.scans import ScanService, Scan, ScanStatus, ScanTool, ScanRead
from app.modules.recon import ReconService
from app.modules.findings import FindingService, EvidenceType
from app.modules.web_assessment.types import CapturedResponse, CandidateFinding
from app.modules.web_assessment.schemas import WebAssessmentRequest
from app.modules.web_assessment.runners.curl_runner import CurlRunner
from app.modules.web_assessment.runners.tls_runner import TlsRunner
from app.modules.web_assessment.runners.zap_runner import ZapRunner, filter_spidered_urls
from app.modules.web_assessment.checks import (
    VALID_CATEGORIES,
    check_security_headers,
    check_cors_configuration,
    check_plain_http_target,
    check_http_to_https_redirect,
    check_tls_configuration,
    check_exposed_file,
    DEFAULT_EXPOSED_PATHS,
    parse_robots_txt,
    check_banner_headers,
    check_verbose_error_pages,
    check_sensitive_content,
    check_cookie_attributes,
)

ALLOWED_OPTIONS = {"delay_ms", "max_requests", "per_request_timeout", "max_body_bytes"}
ALLOWED_ZAP_OPTIONS = {"spider_max_depth", "spider_duration_mins", "run_active_scan"}


def _candidate_identity(candidate: CandidateFinding) -> tuple[str, str, str]:
    """Normalize known curl/ZAP title variants for cross-tool evidence merging."""
    title = candidate.title.casefold().replace("[zap]", "").strip()
    normalized = " ".join(title.split())
    if (
        ("content security policy" in normalized or "csp" in normalized)
        and any(marker in normalized for marker in ("not set", "missing", "not present"))
    ):
        normalized = "missing content-security-policy header"
    return candidate.category, candidate.severity.value, normalized


def _merge_zap_with_curl_candidates(
    candidates: List[CandidateFinding],
) -> List[CandidateFinding]:
    """Combine equivalent ZAP and curl findings while retaining both evidence sources."""
    merged: List[CandidateFinding] = []
    curl_candidates: Dict[tuple[str, str, str], CandidateFinding] = {}
    for candidate in candidates:
        identity = _candidate_identity(candidate)
        is_zap = candidate.title.startswith("[ZAP]")
        curl_match = curl_candidates.get(identity)
        if is_zap and curl_match is not None:
            curl_label = curl_match.evidence_label or "Curl check"
            zap_label = candidate.evidence_label or "ZAP alert"
            curl_evidence = curl_match.evidence_content or ""
            zap_evidence = candidate.evidence_content or ""
            curl_match.evidence_label = "Curl and ZAP evidence"
            curl_match.evidence_content = (
                f"[{curl_label}]\n{curl_evidence}\n\n"
                f"[{zap_label}]\n{zap_evidence}"
            )
            continue

        merged.append(candidate)
        if not is_zap:
            curl_candidates.setdefault(identity, candidate)
    return merged


class WebAssessmentService:
    """Public orchestration service for Web Application Security Assessments."""

    def __init__(self, db: Session):
        self.db = db
        self.assessment_service = AssessmentService(db)
        self.target_service = TargetService(db)
        self.scan_service = ScanService(db)
        self.recon_service = ReconService(db)
        self.audit_service = AuditService(db)
        self.finding_service = FindingService(db)

    def trigger_web_assessment(
        self,
        assessment_id: uuid.UUID,
        request: WebAssessmentRequest,
        background_tasks: BackgroundTasks,
        user_id: Optional[uuid.UUID] = None,
    ) -> ScanRead:
        """
        Validate assessment, target, categories, and options before initiating scan.
        Enforces mandatory scope validation, creates parent scan row, logs audit trail,
        and enqueues background scan worker.
        """
        # 1. Verify assessment exists
        assessment = self.assessment_service.get_assessment(assessment_id)
        if not assessment:
            raise NotFoundException("Assessment", assessment_id)

        # 2. Verify target exists
        target = self.target_service.get_target(assessment.target_id)
        if not target:
            raise NotFoundException("Target", assessment.target_id)

        # 3. Validate categories
        categories = request.categories
        if not categories:
            categories = sorted(list(VALID_CATEGORIES))
        else:
            for cat in categories:
                if cat not in VALID_CATEGORIES:
                    raise ValueError(
                        f"Unknown category '{cat}'. Allowed categories: {sorted(list(VALID_CATEGORIES))}"
                    )

        # 4. Validate options allow-list
        options = request.options or {}
        for opt_key in options:
            if opt_key not in ALLOWED_OPTIONS:
                raise ValueError(
                    f"Disallowed option '{opt_key}'. Allowed options: {sorted(list(ALLOWED_OPTIONS))}"
                )

        zap_opts = request.zap_options or {}
        for z_key in zap_opts:
            if z_key not in ALLOWED_ZAP_OPTIONS:
                raise ValueError(
                    f"Disallowed ZAP option '{z_key}'. Allowed zap_options: {sorted(list(ALLOWED_ZAP_OPTIONS))}"
                )

        # 5. Mandatory scope check on target base URL
        in_scope, reason = self.target_service.scope_manager.check_scope(
            assessment.target_id, target.base_url
        )
        if not in_scope:
            rejected_scan = Scan(
                assessment_id=assessment_id,
                tool=ScanTool.CURL,
                command="curl web-assessment",
                status=ScanStatus.REJECTED,
                error=f"Scope violation: {reason}",
                finished_at=datetime.datetime.now(datetime.timezone.utc),
            )
            created_rejected = self.scan_service.repository.create(rejected_scan)

            self.audit_service.log_action(
                action="scan_rejected",
                detail={
                    "assessment_id": str(assessment_id),
                    "scan_id": str(created_rejected.id),
                    "tool": "curl",
                    "target": target.base_url,
                    "reason": reason,
                },
                user_id=user_id,
            )
            raise ScopeViolationException(asset=target.base_url, target_id=assessment.target_id)

        # 6. Concurrency check (one scan at a time per assessment)
        running = self.scan_service.repository.list_running_by_assessment(assessment_id)
        if running:
            raise ValueError(f"Another scan is currently in progress for assessment '{assessment_id}'")

        # 7. Create parent scan row
        scan = Scan(
            assessment_id=assessment_id,
            tool=ScanTool.CURL,
            command=f"curl web-assessment --categories {','.join(categories)}",
            status=ScanStatus.PENDING,
        )
        created_scan = self.scan_service.repository.create(scan)

        # 8. Record audit log
        self.audit_service.log_action(
            action="web_assessment_started",
            detail={
                "assessment_id": str(assessment_id),
                "scan_id": str(created_scan.id),
                "categories": categories,
                "include_zap": request.include_zap,
            },
            user_id=user_id,
        )

        # 9. Enqueue background execution
        background_tasks.add_task(
            self.execute_web_assessment,
            scan_id=created_scan.id,
            categories=categories,
            include_zap=request.include_zap,
            zap_options=zap_opts,
            options=options,
            user_id=user_id,
        )

        return ScanRead.model_validate(created_scan)

    def execute_web_assessment(
        self,
        scan_id: uuid.UUID,
        categories: List[str],
        include_zap: bool,
        zap_options: Dict[str, Any],
        options: Dict[str, Any],
        user_id: Optional[uuid.UUID] = None,
    ) -> Scan:
        """
        Background execution worker for web application security assessment.
        Collects HTTP responses, checks security misconfigurations, runs ZAP if requested,
        deduplicates findings, attaches immutable evidence, and updates scan status.
        """
        scan = self.scan_service.repository.get_by_id(scan_id)
        if not scan:
            raise NotFoundException("Scan", scan_id)

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.datetime.now(datetime.timezone.utc)
        self.scan_service.repository.update(scan)

        assessment = self.assessment_service.get_assessment(scan.assessment_id)
        target = self.target_service.get_target(assessment.target_id)

        curl_runner = CurlRunner(
            db=self.db,
            target_id=target.id,
            user_id=user_id,
            delay_ms=options.get("delay_ms"),
            max_requests=options.get("max_requests"),
        )
        tls_runner = TlsRunner()
        zap_runner = ZapRunner(db=self.db, target_id=target.id)

        full_transcript = f"=== Web Security Assessment for {target.base_url} ===\n"
        full_transcript += f"Categories: {', '.join(categories)}\n"
        full_transcript += f"Started: {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n\n"

        all_candidates: List[CandidateFinding] = []
        captured_responses: List[CapturedResponse] = []

        try:
            # 1. Baseline soft-404 probe
            baseline_path = f"/notfound_baseline_{uuid.uuid4().hex[:8]}"
            baseline_url = urllib.parse.urljoin(target.base_url, baseline_path)
            baseline_res, baseline_log = curl_runner.probe(baseline_url, method="GET")
            full_transcript += f"[BASELINE 404 PROBE]\n{baseline_log}\n"

            # 2. Root URL probe (base_url)
            root_res, root_log = curl_runner.probe(target.base_url, method="GET")
            full_transcript += f"[ROOT TARGET PROBE]\n{root_log}\n"
            if root_res:
                captured_responses.append(root_res)

            # 3. TLS and HTTPS reachability inspection
            parsed_base = urllib.parse.urlsplit(target.base_url)
            host = parsed_base.hostname or "localhost"
            port = parsed_base.port or (443 if parsed_base.scheme == "https" else 80)
            tls_port = 443 if port in (80, 443) else port

            tls_info = tls_runner.check_tls(host=host, port=tls_port)
            full_transcript += f"[TLS INSPECTION]\n{tls_info.get('raw_output')}\n"

            # Check plain HTTP target & redirect
            if parsed_base.scheme == "http":
                all_candidates.extend(
                    check_plain_http_target(target.base_url, tls_info.get("https_available", False))
                )
                if root_res:
                    all_candidates.extend(
                        check_http_to_https_redirect(root_res, tls_info.get("https_available", False))
                    )

            if "security_headers" in categories:
                if tls_info.get("https_available"):
                    all_candidates.extend(check_tls_configuration(tls_info, host))
                if root_res:
                    all_candidates.extend(check_security_headers(root_res))
                    all_candidates.extend(check_cors_configuration(root_res))

            # 4. Exposed files & directories
            if "exposed_files" in categories:
                for probe_path in DEFAULT_EXPOSED_PATHS:
                    probe_url = urllib.parse.urljoin(target.base_url, probe_path)
                    res, log = curl_runner.probe(probe_url, method="GET")
                    full_transcript += f"[PATH PROBE: {probe_path}]\n{log}\n"
                    if res:
                        captured_responses.append(res)
                        candidates = check_exposed_file(res, baseline_res)
                        all_candidates.extend(candidates)

                        # Extract Disallow entries from robots.txt into recon assets
                        if probe_path == "/robots.txt" and res.status == 200:
                            disallowed = parse_robots_txt(res.body)
                            if disallowed:
                                recon_assets = [
                                    {
                                        "type": "endpoint",
                                        "value": urllib.parse.urljoin(target.base_url, dis),
                                        "details": {"source": "robots.txt", "directive": "Disallow"},
                                    }
                                    for dis in disallowed
                                ]
                                self.recon_service.create_assets_from_scan(
                                    assessment_id=assessment.id,
                                    scan_id=scan.id,
                                    parsed_items=recon_assets,
                                )

            # 5. Information disclosure
            if "information_disclosure" in categories:
                if root_res:
                    all_candidates.extend(check_banner_headers(root_res))
                    all_candidates.extend(check_sensitive_content(root_res))

                # Benign error probe to check for stack trace leakage
                err_path = f"/error_trigger_malformed_{uuid.uuid4().hex[:6]}"
                err_url = urllib.parse.urljoin(target.base_url, err_path)
                err_res, err_log = curl_runner.probe(err_url, method="GET")
                full_transcript += f"[ERROR TRIGGER PROBE]\n{err_log}\n"
                if err_res:
                    captured_responses.append(err_res)
                    all_candidates.extend(check_verbose_error_pages(err_res))

            # 6. Session management
            if "session_management" in categories:
                for resp in captured_responses:
                    all_candidates.extend(check_cookie_attributes(resp))

            # 7. ZAP Integration (if requested)
            if include_zap:
                full_transcript += "\n=== OWASP ZAP Execution ===\n"
                oos_items = [
                    item.asset
                    for item in target.scope_items
                    if not item.in_scope
                ]
                run_active = zap_options.get("run_active_scan", False)
                try:
                    zap_candidates, spidered_urls, raw_zap_json = zap_runner.execute_zap_assessment(
                        target_url=target.base_url,
                        out_of_scope_assets=oos_items,
                        run_active_scan=run_active,
                        spider_depth=zap_options.get("spider_max_depth"),
                        spider_duration=zap_options.get("spider_duration_mins"),
                    )
                    cookie_responses: Dict[str, Optional[CapturedResponse]] = {
                        response.url: response
                        for response in captured_responses
                    }
                    for candidate in zap_candidates:
                        if candidate.category != "session_management":
                            all_candidates.append(candidate)
                            continue

                        observed_cookie_evidence: List[str] = []
                        verified_urls: List[str] = []
                        candidate_urls = candidate.affected_urls or [candidate.affected_url]
                        for candidate_url in candidate_urls:
                            evidence_response = cookie_responses.get(candidate_url)
                            if candidate_url not in cookie_responses:
                                evidence_response, evidence_log = curl_runner.probe(
                                    candidate_url,
                                    method="GET",
                                )
                                full_transcript += (
                                    f"[ZAP SESSION EVIDENCE PROBE: {candidate_url}]\n"
                                    f"{evidence_log}\n"
                                )
                                if evidence_response:
                                    captured_responses.append(evidence_response)
                                cookie_responses[candidate_url] = evidence_response

                            set_cookie_headers = (
                                evidence_response.get_headers("Set-Cookie")
                                if evidence_response
                                else []
                            )
                            if not set_cookie_headers:
                                full_transcript += (
                                    "[ZAP SESSION ALERT FILTERED] No captured Set-Cookie "
                                    f"header supported the alert at {candidate_url}.\n"
                                )
                                continue

                            verified_urls.append(candidate_url)
                            observed_cookie_evidence.extend(
                                [
                                    f"URL: {candidate_url}",
                                    *(
                                        f"Set-Cookie: {header}"
                                        for header in set_cookie_headers
                                    ),
                                ]
                            )

                        if not observed_cookie_evidence:
                            continue

                        candidate.affected_url = verified_urls[0]
                        candidate.evidence_label = "ZAP Alert and Observed Set-Cookie Headers"
                        candidate.evidence_content = (
                            f"{candidate.evidence_content or ''}\n\n"
                            "Observed Set-Cookie response headers:\n"
                            + "\n".join(observed_cookie_evidence)
                        )
                        all_candidates.append(candidate)
                    full_transcript += f"ZAP Alerts JSON:\n{raw_zap_json}\n"

                    # Keep endpoint assets bounded and remove duplicates before persistence.
                    spidered_urls = filter_spidered_urls(spidered_urls)
                    if spidered_urls:
                        zap_assets = [
                            {
                                "type": "endpoint",
                                "value": u,
                                "details": {"source": "zap_spider"},
                            }
                            for u in spidered_urls
                        ]
                        self.recon_service.create_assets_from_scan(
                            assessment_id=assessment.id,
                            scan_id=scan.id,
                            parsed_items=zap_assets,
                        )

                except Exception as zap_err:
                    scan.error = f"OWASP ZAP failed: {zap_err}"
                    full_transcript += f"[ZAP TOOL FAILURE] {scan.error}\n"
                    self.audit_service.log_action(
                        action="web_assessment_tool_failed",
                        detail={
                            "scan_id": str(scan.id),
                            "tool": "zap",
                            "error": scan.error,
                            "curl_results_saved": True,
                        },
                        user_id=user_id,
                    )

            all_candidates = _merge_zap_with_curl_candidates(all_candidates)

            # 8. Ingest Candidate Findings with Deduplication & Immutable Evidence
            for cand in all_candidates:
                self.finding_service.ingest_candidate(
                    assessment_id=assessment.id,
                    scan_id=scan.id,
                    title=cand.title,
                    category=cand.category,
                    description=cand.description,
                    severity=cand.severity,
                    affected_url=cand.affected_url,
                    cvss_score=cand.cvss_score,
                    cvss_vector=cand.cvss_vector,
                    wstg_id=cand.wstg_id,
                    owasp_top10=cand.owasp_top10,
                    cwe=cand.cwe,
                    remediation=cand.remediation,
                    evidence_content=cand.evidence_content,
                    evidence_label=cand.evidence_label,
                    evidence_type=EvidenceType.REQUEST_RESPONSE,
                )

            # 9. Complete scan successfully
            full_transcript += f"\nAssessment Finished: {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n"
            full_transcript += f"Total Candidate Findings: {len(all_candidates)}\n"

            scan.raw_output = full_transcript
            scan.status = ScanStatus.COMPLETED
            scan.finished_at = datetime.datetime.now(datetime.timezone.utc)
            self.scan_service.repository.update(scan)

            self.audit_service.log_action(
                action="web_assessment_completed",
                detail={
                    "assessment_id": str(assessment.id),
                    "scan_id": str(scan.id),
                    "findings_count": len(all_candidates),
                },
                user_id=user_id,
            )
            return scan

        except Exception as exc:
            scan.status = ScanStatus.FAILED
            scan.error = f"Web assessment failure: {exc}"
            scan.finished_at = datetime.datetime.now(datetime.timezone.utc)
            scan.raw_output = full_transcript
            self.scan_service.repository.update(scan)

            self.audit_service.log_action(
                action="web_assessment_failed",
                detail={"assessment_id": str(assessment.id), "scan_id": str(scan.id), "error": str(exc)},
                user_id=user_id,
            )
            return scan
