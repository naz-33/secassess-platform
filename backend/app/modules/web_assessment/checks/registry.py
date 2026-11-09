from typing import Dict, List, Callable, Any
from app.modules.web_assessment.checks.security_headers import (
    check_security_headers,
    check_cors_configuration,
    check_plain_http_target,
    check_http_to_https_redirect,
    check_tls_configuration,
)
from app.modules.web_assessment.checks.exposed_files import (
    check_exposed_file,
    DEFAULT_EXPOSED_PATHS,
    is_soft_404,
    parse_robots_txt,
)
from app.modules.web_assessment.checks.information_disclosure import (
    check_banner_headers,
    check_verbose_error_pages,
    check_sensitive_content,
)
from app.modules.web_assessment.checks.session_management import (
    check_cookie_attributes,
    check_session_fixation,
)

VALID_CATEGORIES = {
    "security_headers",
    "exposed_files",
    "information_disclosure",
    "session_management",
}

CHECK_REGISTRY: Dict[str, Dict[str, Any]] = {
    "security_headers": {
        "name": "Security Configuration and HTTPS",
        "wstg": ["WSTG-CONF-07", "WSTG-CRYP-01"],
        "owasp": ["A02:2021-Cryptographic Failures", "A05:2021-Security Misconfiguration"],
        "response_checks": [check_security_headers, check_cors_configuration],
    },
    "exposed_files": {
        "name": "Exposed Files and Directories",
        "wstg": ["WSTG-CONF-04", "WSTG-CONF-05"],
        "owasp": ["A05:2021-Security Misconfiguration"],
        "path_list": DEFAULT_EXPOSED_PATHS,
        "check": check_exposed_file,
    },
    "information_disclosure": {
        "name": "Information Disclosure",
        "wstg": ["WSTG-INFO-02", "WSTG-INFO-05", "WSTG-ERRH-01"],
        "owasp": ["A05:2021-Security Misconfiguration"],
        "response_checks": [check_banner_headers, check_verbose_error_pages, check_sensitive_content],
    },
    "session_management": {
        "name": "Session Management and Cookie Attributes",
        "wstg": ["WSTG-SESS-01", "WSTG-SESS-02", "WSTG-SESS-03"],
        "owasp": ["A07:2021-Identification and Authentication Failures"],
        "cookie_checks": [check_cookie_attributes],
    },
}


def get_registered_categories() -> List[str]:
    """Return all valid category identifiers."""
    return sorted(list(VALID_CATEGORIES))

