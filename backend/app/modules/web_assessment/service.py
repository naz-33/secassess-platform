from sqlalchemy.orm import Session
from app.modules.web_assessment.schemas import WebScanRequest, WebScanResult


class WebAssessmentService:
    """Public business logic service for web vulnerability assessment."""

    def __init__(self, db: Session):
        self.db = db

    def run_web_scan(self, request: WebScanRequest) -> WebScanResult:
        """
        Execute web vulnerability assessment against target_url.
        MUST verify scope via TargetService before performing active HTTP probes.
        """
        # TODO: Call TargetService(db).assert_in_scope(request.target_id, request.target_url)
        # TODO: Dispatch scan through ZapRunner / CurlRunner / TlsRunner
        raise NotImplementedError("Web assessment execution not yet implemented")
