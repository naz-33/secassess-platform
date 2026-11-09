"""Public API for Web Assessment module."""
from app.modules.web_assessment.service import WebAssessmentService
from app.modules.web_assessment.schemas import WebAssessmentRequest
from app.modules.web_assessment.types import CapturedResponse, CandidateFinding
from app.modules.web_assessment.checks.registry import CHECK_REGISTRY, VALID_CATEGORIES

__all__ = [
    "WebAssessmentService",
    "WebAssessmentRequest",
    "CapturedResponse",
    "CandidateFinding",
    "CHECK_REGISTRY",
    "VALID_CATEGORIES",
]
