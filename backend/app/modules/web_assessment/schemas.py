import uuid
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, ConfigDict, Field, StrictInt
from app.core.config import settings


class WebAssessmentOptions(BaseModel):
    """Bounded execution options for web assessment HTTP probing."""

    model_config = ConfigDict(extra="forbid")

    delay_ms: Optional[StrictInt] = Field(
        default=None,
        ge=settings.WEB_RATE_LIMIT_DELAY_MS,
        description=f"Delay between HTTP probes in milliseconds (minimum {settings.WEB_RATE_LIMIT_DELAY_MS}).",
    )
    max_requests: Optional[StrictInt] = Field(
        default=None,
        ge=1,
        le=settings.WEB_MAX_REQUESTS_CAP,
        description=f"Maximum number of HTTP probes (1 to {settings.WEB_MAX_REQUESTS_CAP}).",
    )
    per_request_timeout: Optional[StrictInt] = Field(
        default=None,
        ge=1,
        le=settings.WEB_REQUEST_TIMEOUT_SECONDS,
        description=f"Per-request timeout in seconds (1 to {settings.WEB_REQUEST_TIMEOUT_SECONDS}).",
    )
    max_body_bytes: Optional[StrictInt] = Field(
        default=None,
        ge=1,
        le=settings.WEB_MAX_BODY_SIZE_BYTES,
        description=f"Maximum response body size in bytes (1 to {settings.WEB_MAX_BODY_SIZE_BYTES}).",
    )


class WebAssessmentRequest(BaseModel):
    """Payload for triggering a web application security assessment."""
    categories: Optional[List[str]] = Field(
        default=None,
        description="Categories to evaluate: security_headers, exposed_files, information_disclosure, session_management.",
    )
    include_zap: bool = Field(
        default=False,
        description="Whether to run OWASP ZAP spider and passive vulnerability scan.",
    )
    zap_options: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description=(
            "Allow-listed ZAP options: spider_max_depth (hard-capped at 5), "
            "spider_duration_mins, and run_active_scan. The spider URL count uses "
            "ZAP_SPIDER_MAX_URLS and is hard-capped at 500."
        ),
    )
    options: Optional[WebAssessmentOptions] = Field(
        default_factory=WebAssessmentOptions,
        description="Bounded execution options: delay_ms, max_requests, per_request_timeout, max_body_bytes.",
    )
