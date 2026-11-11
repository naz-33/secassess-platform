import uuid
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


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
    options: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Allow-listed execution options: delay_ms, max_requests, per_request_timeout.",
    )
