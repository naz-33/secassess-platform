"""Business logic and orchestration service for AI-assisted security analysis."""
import hashlib
import logging
import re
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Any
from fastapi import BackgroundTasks
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.exceptions import (
    NotFoundException,
    ForbiddenException,
    ConflictException,
    UnprocessableEntityException,
    RateLimitException,
)
from app.modules.audit import AuditService
from app.modules.auth import User
from app.modules.assessments import AssessmentService
from app.modules.scans import ScanService
from app.modules.findings import (
    FindingService,
    FindingRead,
    FindingStatus,
    FindingSeverity,
    FindingSource,
)
from app.modules.targets import TargetService

from app.modules.ai_analysis.models import (
    AIAnalysis,
    AIFunction,
    AIAnalysisStatus,
    AIReviewStatus,
)
from app.modules.ai_analysis.repository import AIAnalysisRepository
from app.modules.ai_analysis.redaction import redact_scan_output, redact_text
from app.modules.ai_analysis.gemini_client import call_gemini_api
from app.modules.ai_analysis.schemas import (
    ScanInterpretationResponse,
    PrioritizationResponse,
    FindingExplanationResponse,
    ExecutiveSummaryResponse,
    AIAnalysisRead,
    AIStatusRead,
    PromoteSuggestionRequest,
    ReviewAnalysisRequest,
)

logger = logging.getLogger(__name__)

PROMPT_VERSION = "v1"
PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"

# Allowed reference formats: WSTG, CWE, OWASP identifiers (never arbitrary URLs)
ALLOWED_REFERENCE_PATTERN = re.compile(
    r"^(WSTG-[A-Z0-9\-]+|CWE-\d+|OWASP-[A-Z0-9\-]+|A0?[1-9]:20[12]\d(-[A-Za-z0-9\-]+)?)$",
    re.IGNORECASE,
)


def _load_prompt_template(name: str) -> str:
    path = PROMPTS_DIR / f"{name}_{PROMPT_VERSION}.md"
    if not path.exists():
        raise FileNotFoundError(f"Prompt template file not found: {path}")
    return path.read_text(encoding="utf-8")


def _execute_ai_analysis_background_worker(analysis_id: uuid.UUID) -> None:
    """Isolated background worker executing AI analysis and persisting results."""
    db = SessionLocal()
    try:
        service = AIAnalysisService(db)
        service._run_analysis_pipeline(analysis_id)
    except Exception as exc:
        logger.exception("Unexpected error in AI background worker for %s: %s", analysis_id, exc)
    finally:
        db.close()


class AIAnalysisService:
    """Public service managing AI reasoning, scan interpretations, prioritization, and summaries."""

    def __init__(self, db: Session):
        self.db = db
        self.repository = AIAnalysisRepository(db)
        self.assessment_service = AssessmentService(db)
        self.scan_service = ScanService(db)
        self.finding_service = FindingService(db)
        self.target_service = TargetService(db)
        self.audit_service = AuditService(db)

    # =========================================================================
    # Status and Budget Inquiries
    # =========================================================================

    def get_status(self, user: User) -> AIStatusRead:
        """Return AI readiness, active model, and remaining quota without leaking keys."""
        one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
        used_this_hour = self.repository.count_calls_for_user_since(user.id, one_hour_ago)
        remaining_hourly = max(0, settings.AI_MAX_CALLS_PER_USER_PER_HOUR - used_this_hour)

        return AIStatusRead(
            enabled=settings.AI_ENABLED,
            configured=bool(settings.GEMINI_API_KEY and settings.GEMINI_API_KEY.strip()),
            model=settings.GEMINI_MODEL,
            limits={
                "max_calls_per_assessment": settings.AI_MAX_CALLS_PER_ASSESSMENT,
                "max_calls_per_user_per_hour": settings.AI_MAX_CALLS_PER_USER_PER_HOUR,
            },
            remaining_budget={
                "user_hourly_remaining": remaining_hourly,
                "user_hourly_used": used_this_hour,
            },
        )

    def _assert_quota(self, assessment_id: uuid.UUID, user: User) -> None:
        """Enforce per-assessment and per-user hourly rate limits."""
        assessment_calls = self.repository.count_calls_for_assessment(assessment_id)
        if assessment_calls >= settings.AI_MAX_CALLS_PER_ASSESSMENT:
            raise RateLimitException(
                f"Assessment call budget of {settings.AI_MAX_CALLS_PER_ASSESSMENT} exceeded for assessment {assessment_id}."
            )

        one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
        user_calls = self.repository.count_calls_for_user_since(user.id, one_hour_ago)
        if user_calls >= settings.AI_MAX_CALLS_PER_USER_PER_HOUR:
            raise RateLimitException(
                f"User hourly call limit of {settings.AI_MAX_CALLS_PER_USER_PER_HOUR} exceeded. Please try again later."
            )

    # =========================================================================
    # Trigger AI Functions (Async BackgroundTasks Returning 202)
    # =========================================================================

    def trigger_scan_interpretation(
        self,
        assessment_id: uuid.UUID,
        scan_id: uuid.UUID,
        user: User,
        force: bool = False,
        background_tasks: Optional[BackgroundTasks] = None,
    ) -> AIAnalysisRead:
        """Analyze tool scan results to extract key observations and suggested candidate findings."""
        assessment = self.assessment_service.get_assessment(assessment_id)
        if not assessment:
            raise NotFoundException("Assessment", assessment_id)

        scan = self.scan_service.get_scan(scan_id)
        if not scan:
            raise NotFoundException("Scan", scan_id)

        if scan.assessment_id != assessment_id:
            raise ConflictException(f"Scan {scan_id} does not belong to assessment {assessment_id}.")

        # Check quota unless reusing cache
        self._assert_quota(assessment_id, user)

        # Prepare raw context string
        raw_output = scan.raw_output or "No output captured for scan."

        # Redact context
        redacted = redact_scan_output(
            raw_output,
            max_chars=settings.AI_MAX_INPUT_CHARS,
            redact_internal_ips=settings.AI_REDACT_INTERNAL_IPS,
        )
        input_hash = hashlib.sha256(redacted.text.encode("utf-8")).hexdigest()

        # Check cache
        if not force:
            cached = self.repository.find_cached_analysis(
                assessment_id=assessment_id,
                function=AIFunction.INTERPRET,
                input_hash=input_hash,
                prompt_version=PROMPT_VERSION,
            )
            if cached:
                return self._to_read_dto(cached)

        # Create pending analysis row
        analysis = AIAnalysis(
            assessment_id=assessment_id,
            scan_id=scan_id,
            function=AIFunction.INTERPRET,
            status=AIAnalysisStatus.PENDING,
            requested_by=user.id,
            model=settings.GEMINI_MODEL,
            prompt_version=PROMPT_VERSION,
            prompt_summary=f"Scan interpretation for {scan.tool.value} scan {scan_id}",
            input_hash=input_hash,
            redaction_report=redacted.report.to_dict(),
        )
        created = self.repository.create(analysis)

        self._audit_start(created, user)

        if background_tasks is not None:
            background_tasks.add_task(_execute_ai_analysis_background_worker, created.id)
        else:
            self._run_analysis_pipeline(created.id)
            refreshed = self.repository.get_by_id(created.id)
            return self._to_read_dto(refreshed or created)

        return self._to_read_dto(created)

    def trigger_prioritization(
        self,
        assessment_id: uuid.UUID,
        user: User,
        force: bool = False,
        background_tasks: Optional[BackgroundTasks] = None,
    ) -> AIAnalysisRead:
        """Prioritize assessment findings and formulate actionable remediation steps."""
        assessment = self.assessment_service.get_assessment(assessment_id)
        if not assessment:
            raise NotFoundException("Assessment", assessment_id)

        self._assert_quota(assessment_id, user)

        findings = self.finding_service.list_findings(assessment_id, limit=200)
        findings_summary_items = []
        for f in findings:
            findings_summary_items.append(
                f"- ID: {f.id} | Title: {f.title} | Category: {f.category} | "
                f"Status: {f.status.value} | Effective Severity: {f.effective_severity.value} | "
                f"URL: {f.affected_url or 'N/A'}\n  Description: {f.description[:200]}"
            )
        raw_findings_text = "\n".join(findings_summary_items) or "No findings recorded for this assessment."

        redacted = redact_text(
            raw_findings_text,
            max_chars=settings.AI_MAX_INPUT_CHARS,
            redact_internal_ips=settings.AI_REDACT_INTERNAL_IPS,
        )
        input_hash = hashlib.sha256(redacted.text.encode("utf-8")).hexdigest()

        if not force:
            cached = self.repository.find_cached_analysis(
                assessment_id=assessment_id,
                function=AIFunction.PRIORITIZE,
                input_hash=input_hash,
                prompt_version=PROMPT_VERSION,
            )
            if cached:
                return self._to_read_dto(cached)

        analysis = AIAnalysis(
            assessment_id=assessment_id,
            function=AIFunction.PRIORITIZE,
            status=AIAnalysisStatus.PENDING,
            requested_by=user.id,
            model=settings.GEMINI_MODEL,
            prompt_version=PROMPT_VERSION,
            prompt_summary=f"Risk prioritization for assessment {assessment_id} ({len(findings)} findings)",
            input_hash=input_hash,
            redaction_report=redacted.report.to_dict(),
        )
        created = self.repository.create(analysis)

        self._audit_start(created, user)

        if background_tasks is not None:
            background_tasks.add_task(_execute_ai_analysis_background_worker, created.id)
        else:
            self._run_analysis_pipeline(created.id)
            refreshed = self.repository.get_by_id(created.id)
            return self._to_read_dto(refreshed or created)

        return self._to_read_dto(created)

    def trigger_finding_explanation(
        self,
        finding_id: uuid.UUID,
        user: User,
        force: bool = False,
        background_tasks: Optional[BackgroundTasks] = None,
    ) -> AIAnalysisRead:
        """Deep technical explanation and specific remediation guidance for a single finding."""
        finding = self.finding_service.get_finding(finding_id)
        if not finding:
            raise NotFoundException("Finding", finding_id)

        self._assert_quota(finding.assessment_id, user)

        evidences = self.finding_service.list_evidence_for_finding(finding_id)
        evidence_text_parts = []
        for e in evidences:
            content_snippet = (e.content or "")[:1000]
            evidence_text_parts.append(f"Evidence ID: {e.id} [{e.type.value}]: {content_snippet}")

        raw_context = (
            f"Title: {finding.title}\n"
            f"Category: {finding.category}\n"
            f"Status: {finding.status.value}\n"
            f"Effective Severity: {finding.effective_severity.value}\n"
            f"Affected URL: {finding.affected_url or 'N/A'}\n"
            f"Description: {finding.description}\n"
            f"Existing Remediation: {finding.remediation or 'None'}\n"
            f"Evidences:\n" + "\n".join(evidence_text_parts)
        )

        redacted = redact_text(
            raw_context,
            max_chars=settings.AI_MAX_INPUT_CHARS,
            redact_internal_ips=settings.AI_REDACT_INTERNAL_IPS,
        )
        input_hash = hashlib.sha256(redacted.text.encode("utf-8")).hexdigest()

        if not force:
            cached = self.repository.find_cached_analysis(
                assessment_id=finding.assessment_id,
                function=AIFunction.EXPLAIN,
                input_hash=input_hash,
                prompt_version=PROMPT_VERSION,
            )
            if cached and cached.finding_id == finding_id:
                return self._to_read_dto(cached)

        analysis = AIAnalysis(
            assessment_id=finding.assessment_id,
            finding_id=finding_id,
            function=AIFunction.EXPLAIN,
            status=AIAnalysisStatus.PENDING,
            requested_by=user.id,
            model=settings.GEMINI_MODEL,
            prompt_version=PROMPT_VERSION,
            prompt_summary=f"Technical explanation for finding {finding_id} ({finding.title})",
            input_hash=input_hash,
            redaction_report=redacted.report.to_dict(),
        )
        created = self.repository.create(analysis)

        self._audit_start(created, user)

        if background_tasks is not None:
            background_tasks.add_task(_execute_ai_analysis_background_worker, created.id)
        else:
            self._run_analysis_pipeline(created.id)
            refreshed = self.repository.get_by_id(created.id)
            return self._to_read_dto(refreshed or created)

        return self._to_read_dto(created)

    def trigger_executive_summary(
        self,
        assessment_id: uuid.UUID,
        user: User,
        force: bool = False,
        background_tasks: Optional[BackgroundTasks] = None,
    ) -> AIAnalysisRead:
        """Draft executive summary grounded exclusively in confirmed assessment findings."""
        assessment = self.assessment_service.get_assessment(assessment_id)
        if not assessment:
            raise NotFoundException("Assessment", assessment_id)

        target = self.target_service.get_target(assessment.target_id)
        scope_items = self.target_service.list_scope_items(assessment.target_id) if target else []

        self._assert_quota(assessment_id, user)

        findings = self.finding_service.list_findings(assessment_id, limit=200)

        # Factual grounding: confirmed findings ONLY
        confirmed_findings = [f for f in findings if f.status == FindingStatus.CONFIRMED]
        unverified_count = sum(1 for f in findings if f.status == FindingStatus.UNVERIFIED)
        false_positive_count = sum(1 for f in findings if f.status == FindingStatus.FALSE_POSITIVE)

        confirmed_text_parts = []
        for f in confirmed_findings:
            confirmed_text_parts.append(
                f"- [CONFIRMED] {f.title} (Severity: {f.effective_severity.value}, Category: {f.category}): {f.description[:250]}"
            )

        confirmed_block = "\n".join(confirmed_text_parts) if confirmed_findings else "ZERO CONFIRMED FINDINGS."

        raw_context = (
            f"Assessment: {assessment.name}\n"
            f"Target: {target.name if target else 'N/A'} ({target.base_url if target else 'N/A'})\n"
            f"Scope Items: {len(scope_items)}\n"
            f"Confirmed Count: {len(confirmed_findings)}\n"
            f"Unverified Count: {unverified_count}\n"
            f"False Positive Count: {false_positive_count}\n"
            f"Confirmed Details:\n{confirmed_block}"
        )

        redacted = redact_text(
            raw_context,
            max_chars=settings.AI_MAX_INPUT_CHARS,
            redact_internal_ips=settings.AI_REDACT_INTERNAL_IPS,
        )
        input_hash = hashlib.sha256(redacted.text.encode("utf-8")).hexdigest()

        if not force:
            cached = self.repository.find_cached_analysis(
                assessment_id=assessment_id,
                function=AIFunction.SUMMARIZE,
                input_hash=input_hash,
                prompt_version=PROMPT_VERSION,
            )
            if cached:
                return self._to_read_dto(cached)

        analysis = AIAnalysis(
            assessment_id=assessment_id,
            function=AIFunction.SUMMARIZE,
            status=AIAnalysisStatus.PENDING,
            requested_by=user.id,
            model=settings.GEMINI_MODEL,
            prompt_version=PROMPT_VERSION,
            prompt_summary=f"Executive summary for assessment {assessment_id} ({len(confirmed_findings)} confirmed findings)",
            input_hash=input_hash,
            redaction_report=redacted.report.to_dict(),
        )
        created = self.repository.create(analysis)

        self._audit_start(created, user)

        if background_tasks is not None:
            background_tasks.add_task(_execute_ai_analysis_background_worker, created.id)
        else:
            self._run_analysis_pipeline(created.id)
            refreshed = self.repository.get_by_id(created.id)
            return self._to_read_dto(refreshed or created)

        return self._to_read_dto(created)

    # =========================================================================
    # Retrieval, Review, and Candidate Promotion
    # =========================================================================

    def get_analysis(self, analysis_id: uuid.UUID) -> Optional[AIAnalysisRead]:
        """Fetch analysis record by ID."""
        analysis = self.repository.get_by_id(analysis_id)
        if not analysis:
            return None
        return self._to_read_dto(analysis)

    def list_analyses_for_assessment(
        self,
        assessment_id: uuid.UUID,
        function: Optional[AIFunction] = None,
        status: Optional[AIAnalysisStatus] = None,
        review_status: Optional[AIReviewStatus] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AIAnalysisRead]:
        """List AI analyses associated with an assessment."""
        records = self.repository.list_by_assessment(
            assessment_id=assessment_id,
            function=function,
            status=status,
            review_status=review_status,
            limit=limit,
            offset=offset,
        )
        return [self._to_read_dto(a) for a in records]

    def promote_candidate_suggestion(
        self,
        analysis_id: uuid.UUID,
        promote_in: PromoteSuggestionRequest,
        user: User,
    ) -> FindingRead:
        """
        Promote an AI candidate finding into an official unverified finding.
        Strict Safety Invariant:
        - Created with source='ai' and status='unverified'.
        - Linked to cited evidence and ai_analysis_id.
        - De-duplicated with Phase 3 fingerprint logic.
        - NEVER alters any existing finding's status or severity.
        """
        user_role = user.role.value if hasattr(user.role, "value") else str(user.role)
        if user_role not in ("assessor", "admin"):
            raise ForbiddenException("Only assessors and administrators can promote AI suggestions.")

        analysis = self.repository.get_by_id(analysis_id)
        if not analysis:
            raise NotFoundException("AIAnalysis", analysis_id)

        if analysis.status != AIAnalysisStatus.COMPLETED or analysis.function != AIFunction.INTERPRET:
            raise ConflictException(
                "Only completed scan interpretations contain candidate suggestions that can be promoted."
            )

        response_json = analysis.response_json or {}
        candidates = response_json.get("suggested_candidate_findings", [])
        if promote_in.suggestion_index < 0 or promote_in.suggestion_index >= len(candidates):
            raise UnprocessableEntityException(
                f"Invalid suggestion_index {promote_in.suggestion_index}. Scan interpretation contains {len(candidates)} suggestions."
            )

        candidate = candidates[promote_in.suggestion_index]

        # Extract cited evidence UUIDs
        cited_evidence_ids: List[uuid.UUID] = []
        for eid_str in candidate.get("evidence_ids", []):
            try:
                cited_evidence_ids.append(uuid.UUID(str(eid_str)))
            except ValueError:
                pass

        suggested_sev = FindingSeverity(candidate.get("suggested_severity", "low"))

        # Promote via FindingService public API
        promoted = self.finding_service.promote_ai_suggestion(
            assessment_id=analysis.assessment_id,
            ai_analysis_id=analysis.id,
            title=candidate.get("title", "AI Proposed Finding"),
            category=candidate.get("category", "other"),
            description=(
                candidate.get("explanation")
                or candidate.get("description")
                or "No description provided."
            ),
            suggested_severity=suggested_sev,
            scan_id=analysis.scan_id,
            wstg_id=candidate.get("wstg_id"),
            remediation=candidate.get("recommended_fix") or candidate.get("remediation"),
            affected_url=candidate.get("affected_url"),
            evidence_ids=cited_evidence_ids,
        )

        self.audit_service.log_action(
            action="ai_suggestion_promoted",
            detail={
                "analysis_id": str(analysis.id),
                "suggestion_index": promote_in.suggestion_index,
                "promoted_finding_id": str(promoted.id),
                "title": promoted.title,
                "source": promoted.source.value,
                "status": promoted.status.value,
            },
            user_id=user.id,
        )

        return promoted

    def review_analysis(
        self,
        analysis_id: uuid.UUID,
        review_in: ReviewAnalysisRequest,
        user: User,
    ) -> AIAnalysisRead:
        """
        Assessor review for executive summaries and analyses (approve / reject).
        Safety Guarantee:
        The original AI-generated text in response_json remains IMMUTABLE.
        Assessor edits are stored exclusively in edited_text.
        """
        user_role = user.role.value if hasattr(user.role, "value") else str(user.role)
        if user_role not in ("assessor", "admin"):
            raise ForbiddenException("Only assessors and administrators can review AI analyses.")

        analysis = self.repository.get_by_id(analysis_id)
        if not analysis:
            raise NotFoundException("AIAnalysis", analysis_id)

        if analysis.status != AIAnalysisStatus.COMPLETED:
            raise ConflictException("Only completed AI analyses can be reviewed.")

        analysis.review_status = review_in.review_status
        analysis.reviewed_by = user.id
        analysis.reviewed_at = datetime.now(timezone.utc)
        if review_in.edited_text is not None:
            analysis.edited_text = review_in.edited_text
        if review_in.notes is not None:
            analysis.review_notes = review_in.notes

        updated = self.repository.update(analysis)

        self.audit_service.log_action(
            action="ai_analysis_reviewed",
            detail={
                "analysis_id": str(analysis.id),
                "review_status": review_in.review_status.value,
                "has_edits": bool(review_in.edited_text),
                "has_notes": bool(review_in.notes),
            },
            user_id=user.id,
        )

        return self._to_read_dto(updated)

    def get_ai_dashboard_summary(self, assessment_id: uuid.UUID) -> Dict[str, Any]:
        """Aggregate AI metrics, approval statuses, and AI-promoted finding counts."""
        summary = self.repository.get_summary(assessment_id)
        # Fetch AI-promoted findings from FindingService public interface
        ai_findings = self.finding_service.list_findings(
            assessment_id=assessment_id,
            source=FindingSource.AI,
            limit=1000,
        )
        ai_promoted_count = len(ai_findings)
        ai_promoted_confirmed_count = sum(
            1 for f in ai_findings
            if (f.status == FindingStatus.CONFIRMED or getattr(f.status, "value", str(f.status)) == "confirmed")
        )
        summary["ai_promoted_findings_count"] = ai_promoted_count
        summary["ai_promoted_confirmed_count"] = ai_promoted_confirmed_count
        return summary

    def get_approved_executive_summary(self, assessment_id: uuid.UUID) -> Optional[Dict[str, Any]]:
        """Return the approved executive summary record and text for report generation."""
        analysis = self.repository.get_latest_approved_summary(assessment_id)
        if not analysis:
            return None
        summary_text = ""
        if analysis.edited_text and analysis.edited_text.strip():
            summary_text = analysis.edited_text.strip()
        elif analysis.response_json and isinstance(analysis.response_json, dict):
            summary_text = analysis.response_json.get("summary_text", "")

        return {
            "id": analysis.id,
            "model": analysis.model,
            "prompt_version": analysis.prompt_version,
            "summary_text": summary_text,
            "original_text": analysis.response_json.get("summary_text", "") if (analysis.response_json and isinstance(analysis.response_json, dict)) else "",
            "is_edited": bool(analysis.edited_text and analysis.edited_text.strip()),
            "reviewed_by": analysis.reviewed_by,
            "reviewed_at": analysis.reviewed_at,
        }


    # =========================================================================
    # Internal Execution Pipeline & Grounding Validation
    # =========================================================================

    def _run_analysis_pipeline(self, analysis_id: uuid.UUID) -> None:
        """Execute the AI model inference and apply grounding validations."""
        analysis = self.repository.get_by_id(analysis_id)
        if not analysis or analysis.status != AIAnalysisStatus.PENDING:
            return

        try:
            if analysis.function == AIFunction.INTERPRET:
                self._execute_interpret(analysis)
            elif analysis.function == AIFunction.PRIORITIZE:
                self._execute_prioritize(analysis)
            elif analysis.function == AIFunction.EXPLAIN:
                self._execute_explain(analysis)
            elif analysis.function == AIFunction.SUMMARIZE:
                self._execute_summarize(analysis)
            else:
                raise ValueError(f"Unknown analysis function: {analysis.function}")

            analysis.status = AIAnalysisStatus.COMPLETED
            self.repository.update(analysis)

            self.audit_service.log_action(
                action="ai_analysis_completed",
                detail={
                    "analysis_id": str(analysis.id),
                    "function": analysis.function.value,
                    "model": analysis.model,
                    "input_tokens": analysis.input_tokens,
                    "output_tokens": analysis.output_tokens,
                    "latency_ms": analysis.latency_ms,
                },
                user_id=analysis.requested_by,
            )

        except Exception as exc:
            analysis.status = AIAnalysisStatus.FAILED
            # Never include sensitive credentials in stored error
            cleaned_err = str(exc)
            if settings.GEMINI_API_KEY:
                cleaned_err = cleaned_err.replace(settings.GEMINI_API_KEY, "[REDACTED_API_KEY]")
            logger.error("AI analysis pipeline failed for %s: %s", analysis.id, cleaned_err)
            analysis.error = cleaned_err
            self.repository.update(analysis)

            self.audit_service.log_action(
                action="ai_analysis_failed",
                detail={
                    "analysis_id": str(analysis.id),
                    "function": analysis.function.value,
                    "error_class": exc.__class__.__name__,
                },
                user_id=analysis.requested_by,
            )

    def _execute_interpret(self, analysis: AIAnalysis) -> None:
        scan = self.scan_service.get_scan(analysis.scan_id) if analysis.scan_id else None
        if not scan:
            raise NotFoundException("Scan", analysis.scan_id)

        template = _load_prompt_template("interpret")
        raw_output = scan.raw_output or "No output captured."

        # Fetch assessment evidence IDs for citation grounding
        findings = self.finding_service.list_findings(analysis.assessment_id, limit=200)
        valid_evidence_ids = set()
        for f in findings:
            evs = self.finding_service.list_evidence_for_finding(f.id)
            for e in evs:
                valid_evidence_ids.add(str(e.id))

        redacted = redact_scan_output(
            raw_output,
            max_chars=settings.AI_MAX_INPUT_CHARS,
            redact_internal_ips=settings.AI_REDACT_INTERNAL_IPS,
        )

        prompt_body = template.format(
            assessment_id=analysis.assessment_id,
            scan_id=scan.id,
            scan_tool=scan.tool.value,
            scan_target=scan.command or "Target",
            scan_data=redacted.text,
        )

        parsed, response_dict, in_tok, out_tok, lat = call_gemini_api(
            redacted_input=redacted,
            system_instruction=(
                "You are a security analyst. Base every claim only on the supplied scan output; "
                "do not invent evidence and state when evidence is insufficient. Juice Shop may "
                "return the same HTTP 200 single-page index for unknown paths, so an HTTP 200 "
                "alone is not evidence of an exposed file."
            ),
            prompt_content=prompt_body,
            response_schema=ScanInterpretationResponse,
        )

        # Grounding check: verify cited evidence IDs exist in this assessment
        self._ground_citations_interpret(response_dict, valid_evidence_ids)

        analysis.response_json = response_dict
        analysis.input_tokens = in_tok
        analysis.output_tokens = out_tok
        analysis.latency_ms = lat

    def _execute_prioritize(self, analysis: AIAnalysis) -> None:
        template = _load_prompt_template("prioritize")
        findings = self.finding_service.list_findings(analysis.assessment_id, limit=200)
        valid_finding_ids = {str(f.id) for f in findings}

        findings_snippets = []
        for f in findings:
            findings_snippets.append(
                f"- Finding ID: {f.id}\n  Title: {f.title}\n  Category: {f.category}\n"
                f"  Status: {f.status.value}\n  Effective Severity: {f.effective_severity.value}\n"
                f"  URL: {f.affected_url or 'N/A'}\n  Description: {f.description[:300]}"
            )
        raw_text = "\n".join(findings_snippets) or "No findings recorded."
        redacted = redact_text(
            raw_text,
            max_chars=settings.AI_MAX_INPUT_CHARS,
            redact_internal_ips=settings.AI_REDACT_INTERNAL_IPS,
        )

        prompt_body = template.format(
            assessment_id=analysis.assessment_id,
            total_findings=len(findings),
            findings_data=redacted.text,
        )

        parsed, response_dict, in_tok, out_tok, lat = call_gemini_api(
            redacted_input=redacted,
            system_instruction="You are an expert security assessor prioritizing discovered vulnerabilities.",
            prompt_content=prompt_body,
            response_schema=PrioritizationResponse,
        )

        # Grounding check: Filter out non-existent finding IDs and validate reference formats
        self._ground_prioritization(response_dict, valid_finding_ids)

        analysis.response_json = response_dict
        analysis.input_tokens = in_tok
        analysis.output_tokens = out_tok
        analysis.latency_ms = lat

    def _execute_explain(self, analysis: AIAnalysis) -> None:
        template = _load_prompt_template("explain")
        finding = self.finding_service.get_finding(analysis.finding_id) if analysis.finding_id else None
        if not finding:
            raise NotFoundException("Finding", analysis.finding_id)

        evidences = self.finding_service.list_evidence_for_finding(finding.id)
        ev_snippets = [f"Evidence [{e.type.value}]: {(e.content or '')[:800]}" for e in evidences]

        raw_context = (
            f"Title: {finding.title}\nCategory: {finding.category}\nSeverity: {finding.effective_severity.value}\n"
            f"Description: {finding.description}\nURL: {finding.affected_url or 'N/A'}\n"
            f"Evidence:\n" + "\n".join(ev_snippets)
        )
        redacted = redact_text(
            raw_context,
            max_chars=settings.AI_MAX_INPUT_CHARS,
            redact_internal_ips=settings.AI_REDACT_INTERNAL_IPS,
        )

        prompt_body = template.format(
            finding_id=finding.id,
            finding_title=finding.title,
            finding_category=finding.category,
            finding_severity=finding.effective_severity.value,
            finding_data=redacted.text,
        )

        parsed, response_dict, in_tok, out_tok, lat = call_gemini_api(
            redacted_input=redacted,
            system_instruction="You are a principal security researcher giving actionable remediation advice.",
            prompt_content=prompt_body,
            response_schema=FindingExplanationResponse,
        )

        # Validate reference formats
        refs = response_dict.get("references", [])
        validated_refs = [r for r in refs if ALLOWED_REFERENCE_PATTERN.match(r.strip())]
        response_dict["references"] = validated_refs

        analysis.response_json = response_dict
        analysis.input_tokens = in_tok
        analysis.output_tokens = out_tok
        analysis.latency_ms = lat

    def _execute_summarize(self, analysis: AIAnalysis) -> None:
        template = _load_prompt_template("summarize")
        assessment = self.assessment_service.get_assessment(analysis.assessment_id)
        if not assessment:
            raise NotFoundException("Assessment", analysis.assessment_id)

        target = self.target_service.get_target(assessment.target_id)
        scope_items = self.target_service.list_scope_items(assessment.target_id) if target else []

        findings = self.finding_service.list_findings(analysis.assessment_id, limit=200)
        confirmed_findings = [f for f in findings if f.status == FindingStatus.CONFIRMED]
        unverified_count = sum(1 for f in findings if f.status == FindingStatus.UNVERIFIED)
        false_positive_count = sum(1 for f in findings if f.status == FindingStatus.FALSE_POSITIVE)

        confirmed_snippets = []
        for f in confirmed_findings:
            confirmed_snippets.append(
                f"- [CONFIRMED] {f.title} (Effective Severity: {f.effective_severity.value}): {f.description[:250]}"
            )
        confirmed_block = "\n".join(confirmed_snippets) or "ZERO CONFIRMED FINDINGS."

        raw_context = (
            f"Assessment: {assessment.name}\n"
            f"Target: {target.name if target else 'N/A'}\n"
            f"Scope Details: {len(scope_items)} items configured.\n"
            f"Confirmed Findings Count: {len(confirmed_findings)}\n"
            f"Unverified Findings Count: {unverified_count}\n"
            f"Confirmed Details:\n{confirmed_block}"
        )
        redacted = redact_text(
            raw_context,
            max_chars=settings.AI_MAX_INPUT_CHARS,
            redact_internal_ips=settings.AI_REDACT_INTERNAL_IPS,
        )

        prompt_body = template.format(
            assessment_id=assessment.id,
            assessment_name=assessment.name,
            target_name=target.name if target else "Unknown",
            target_base_url=target.base_url if target else "N/A",
            scope_overview=f"{len(scope_items)} assets configured in scope",
            confirmed_count=len(confirmed_findings),
            unverified_count=unverified_count,
            false_positive_count=false_positive_count,
            confirmed_findings_data=redacted.text,
        )

        parsed, response_dict, in_tok, out_tok, lat = call_gemini_api(
            redacted_input=redacted,
            system_instruction="You are a Principal Security Auditor drafting an executive summary based ONLY on confirmed findings.",
            prompt_content=prompt_body,
            response_schema=ExecutiveSummaryResponse,
        )

        analysis.response_json = response_dict
        analysis.input_tokens = in_tok
        analysis.output_tokens = out_tok
        analysis.latency_ms = lat

    # =========================================================================
    # Citation & Grounding Validators
    # =========================================================================

    def _ground_citations_interpret(
        self,
        response_dict: Dict[str, Any],
        valid_evidence_ids: set[str],
    ) -> None:
        """Filter out non-existent or cross-assessment evidence citations and record caveats."""
        caveats = response_dict.setdefault("caveats", [])

        # Filter key_observations citations
        for obs in response_dict.get("key_observations", []):
            cited = obs.get("evidence_ids", [])
            valid_cited = [eid for eid in cited if str(eid) in valid_evidence_ids]
            dropped = set(cited) - set(valid_cited)
            if dropped:
                caveats.append(f"Observation citation(s) {list(dropped)} dropped: not found in assessment.")
            obs["evidence_ids"] = valid_cited

        # Filter candidate findings citations
        for cand in response_dict.get("suggested_candidate_findings", []):
            cited = cand.get("evidence_ids", [])
            valid_cited = [eid for eid in cited if str(eid) in valid_evidence_ids]
            dropped = set(cited) - set(valid_cited)
            if dropped:
                caveats.append(f"Candidate finding citation(s) {list(dropped)} dropped: not found in assessment.")
            cand["evidence_ids"] = valid_cited

    def _ground_prioritization(
        self,
        response_dict: Dict[str, Any],
        valid_finding_ids: set[str],
    ) -> None:
        """Drop non-existent finding IDs and sanitize non-standard references."""
        caveats = response_dict.setdefault("caveats", [])
        prioritized = response_dict.get("prioritized_findings", [])
        valid_items = []

        for item in prioritized:
            fid = str(item.get("finding_id", ""))
            if fid not in valid_finding_ids:
                caveats.append(f"AI prioritized unknown finding_id '{fid}'; entry was dropped.")
                continue

            # Validate reference identifiers
            refs = item.get("references", [])
            valid_refs = []
            for r in refs:
                if ALLOWED_REFERENCE_PATTERN.match(r.strip()):
                    valid_refs.append(r.strip())
                else:
                    caveats.append(f"Non-standard or invented reference '{r}' was removed from finding {fid}.")
            item["references"] = valid_refs
            valid_items.append(item)

        response_dict["prioritized_findings"] = valid_items

    # =========================================================================
    # Helpers
    # =========================================================================

    def _audit_start(self, analysis: AIAnalysis, user: User) -> None:
        self.audit_service.log_action(
            action="ai_analysis_started",
            detail={
                "analysis_id": str(analysis.id),
                "assessment_id": str(analysis.assessment_id),
                "function": analysis.function.value,
                "input_hash": analysis.input_hash,
                "redaction_report": analysis.redaction_report,
            },
            user_id=user.id,
        )

    def _to_read_dto(self, analysis: AIAnalysis) -> AIAnalysisRead:
        return AIAnalysisRead(
            id=analysis.id,
            assessment_id=analysis.assessment_id,
            finding_id=analysis.finding_id,
            scan_id=analysis.scan_id,
            function=analysis.function,
            status=analysis.status,
            requested_by=analysis.requested_by,
            model=analysis.model,
            prompt_version=analysis.prompt_version,
            prompt_summary=analysis.prompt_summary,
            input_hash=analysis.input_hash,
            redaction_report=analysis.redaction_report or {},
            response_json=analysis.response_json,
            error=analysis.error,
            input_tokens=analysis.input_tokens,
            output_tokens=analysis.output_tokens,
            latency_ms=analysis.latency_ms,
            review_status=analysis.review_status,
            reviewed_by=analysis.reviewed_by,
            reviewed_at=analysis.reviewed_at,
            edited_text=analysis.edited_text,
            review_notes=analysis.review_notes,
            created_at=analysis.created_at,
            ai_generated=True,
            disclaimer="AI-generated. Must be verified by an assessor against the evidence.",
        )
