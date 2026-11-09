import re
from typing import List
from app.modules.findings import FindingSeverity
from app.modules.web_assessment.types import CapturedResponse, CandidateFinding

SERVER_BANNER_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Runtime",
    "X-Version",
    "X-Generator",
]

STACK_TRACE_PATTERNS = [
    re.compile(r"Traceback \(most recent call last\):", re.IGNORECASE),
    re.compile(r"at (?:[\w.$]+ )?[\w/\\-]+\.js:\d+:\d+"),
    re.compile(r"at Object\.\w+ \("),
    re.compile(r"org\.springframework\.\w+Exception"),
    re.compile(r"java\.lang\.\w+Exception"),
    re.compile(r"SQLSTATE\[\w+\]", re.IGNORECASE),
    re.compile(r"PostgreSQL query failed:", re.IGNORECASE),
    re.compile(r"Django Version:\s*[\d.]+", re.IGNORECASE),
    re.compile(r"Werkzeug Debugger", re.IGNORECASE),
    re.compile(r"Whoops! There was an error\.", re.IGNORECASE),
]

SENSITIVE_COMMENT_REGEX = re.compile(
    r"<!--(?!\s*\[if)[\s\S]*?(?:TODO|FIXME|password|secret|apikey|token|private|internal)[\s\S]*?-->",
    re.IGNORECASE,
)

INTERNAL_IP_REGEX = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b"
)


def check_banner_headers(response: CapturedResponse) -> List[CandidateFinding]:
    """Flag headers disclosing backend framework or server technology and versions."""
    findings: List[CandidateFinding] = []
    for header_name in SERVER_BANNER_HEADERS:
        val = response.get_header(header_name)
        if val:
            # Check if version or specific product is disclosed
            has_version = bool(re.search(r"\d+\.\d+", val))
            findings.append(
                CandidateFinding(
                    title=f"Server Technology / Version Disclosure ({header_name})",
                    category="information_disclosure",
                    description=f"Response includes '{header_name}: {val}'. Revealing underlying server technology and exact version numbers aids attackers in locating known CVE exploits.",
                    severity=FindingSeverity.LOW if has_version else FindingSeverity.INFO,
                    affected_url=response.url,
                    wstg_id="WSTG-INFO-02",
                    owasp_top10="A05:2021-Security Misconfiguration",
                    cwe="CWE-200",
                    remediation=f"Configure the web server or reverse proxy to suppress or generalize the '{header_name}' header.",
                    evidence_label=f"Banner Header: {header_name}",
                    evidence_content=f"{header_name}: {val}",
                )
            )
    return findings


def check_verbose_error_pages(response: CapturedResponse) -> List[CandidateFinding]:
    """Check if benign error requests return verbose stack traces or database errors."""
    findings: List[CandidateFinding] = []
    body = response.body or ""

    matched_pattern: str = ""
    for pattern in STACK_TRACE_PATTERNS:
        match = pattern.search(body)
        if match:
            matched_pattern = match.group(0)
            break

    if matched_pattern:
        findings.append(
            CandidateFinding(
                title="Verbose Error Page / Stack Trace Disclosure",
                category="information_disclosure",
                description=f"Application response at '{response.url}' contains a stack trace or debug information ('{matched_pattern}'). This exposes internal source file paths, database schemas, and framework internals.",
                severity=FindingSeverity.MEDIUM,
                affected_url=response.url,
                wstg_id="WSTG-ERRH-01",
                owasp_top10="A05:2021-Security Misconfiguration",
                cwe="CWE-209",
                remediation="Disable debug mode in production. Implement custom, generic error pages that do not leak stack traces or system internals to end users.",
                evidence_label="Disclosed Stack Trace / Error Snippet",
                evidence_content=response.raw_text[:2000],
            )
        )
    return findings


def check_sensitive_content(response: CapturedResponse) -> List[CandidateFinding]:
    """Scan response body for sensitive developer comments or internal IP leakages."""
    findings: List[CandidateFinding] = []
    body = response.body or ""

    # Sensitive HTML comments
    comment_matches = SENSITIVE_COMMENT_REGEX.findall(body)
    if comment_matches:
        sample = comment_matches[0].strip()
        findings.append(
            CandidateFinding(
                title="Sensitive Developer Comments in HTML",
                category="information_disclosure",
                description=f"HTML response at '{response.url}' contains comments mentioning sensitive terms (TODO, passwords, internal secrets): {sample[:200]}",
                severity=FindingSeverity.LOW,
                affected_url=response.url,
                wstg_id="WSTG-INFO-05",
                owasp_top10="A05:2021-Security Misconfiguration",
                cwe="CWE-615",
                remediation="Strip comments from client-facing HTML templates during build or release packaging.",
                evidence_label="HTML Comment Snippet",
                evidence_content=sample[:500],
            )
        )

    # Internal IP disclosure
    ip_matches = INTERNAL_IP_REGEX.findall(body)
    if ip_matches:
        unique_ips = list(dict.fromkeys(ip_matches))
        findings.append(
            CandidateFinding(
                title=f"Internal IP Address Disclosure ({', '.join(unique_ips[:3])})",
                category="information_disclosure",
                description=f"Response body discloses RFC 1918 private network IP addresses: {', '.join(unique_ips)}.",
                severity=FindingSeverity.INFO,
                affected_url=response.url,
                wstg_id="WSTG-INFO-05",
                owasp_top10="A05:2021-Security Misconfiguration",
                cwe="CWE-200",
                remediation="Ensure responses do not leak internal infrastructure IP addresses.",
                evidence_label="Internal IPs Disclosed",
                evidence_content=f"Disclosed IPs: {unique_ips}",
            )
        )

    return findings
