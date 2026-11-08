"""Web assessment parsers package."""
from app.modules.web_assessment.parsers.zap_parser import ZapParser
from app.modules.web_assessment.parsers.curl_parser import CurlParser
from app.modules.web_assessment.parsers.tls_parser import TlsParser

__all__ = ["ZapParser", "CurlParser", "TlsParser"]
