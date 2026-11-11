import re
from typing import List, Optional
from app.modules.findings import FindingSeverity
from app.modules.web_assessment.types import CapturedResponse, CandidateFinding

DEFAULT_EXPOSED_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.git/HEAD",
    "/.env",
    "/.DS_Store",
    "/backup",
    "/backup.zip",
    "/admin",
    "/ftp",
    "/package.json",
    "/swagger.json",
    "/api-docs",
    "/.well-known/security.txt",
    "/server-status",
    "/phpinfo.php",
    "/crossdomain.xml",
]

DIRECTORY_LISTING_REGEX = re.compile(
    r"(<title>\s*Index of\s*|<title>\s*listing\s+directory\b|Directory listing for|"
    r"Index of /|\[To Parent Directory\]|<pre><a href=)",
    re.IGNORECASE,
)

ENV_VAR_REGEX = re.compile(r"^[A-Z0-9_]{2,}=.+", re.MULTILINE)


def is_soft_404(
    probe: CapturedResponse,
    baseline: Optional[CapturedResponse],
) -> bool:
    """
    Determine if a response is a soft-404 or SPA catch-all response.
    Juice Shop and many modern SPAs return status 200 with the exact same HTML index page for any route.
    """
    if probe.status != 200:
        return True

    if not baseline:
        return False

    # If baseline is also 200 (like Juice Shop SPA)
    if baseline.status == 200:
        # Check identical content or nearly identical length (within 50 bytes)
        if probe.body == baseline.body:
            return True
        diff_len = abs(len(probe.body) - len(baseline.body))
        if diff_len < 64:
            # Check if title tags are identical
            probe_title = re.findall(r"<title>(.*?)</title>", probe.body, re.IGNORECASE)
            base_title = re.findall(r"<title>(.*?)</title>", baseline.body, re.IGNORECASE)
            if probe_title and base_title and probe_title == base_title:
                return True

    return False


def parse_robots_txt(content: str) -> List[str]:
    """Extract disallowed path endpoints from robots.txt content."""
    endpoints: List[str] = []
    for line in content.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                path = parts[1].strip()
                if path and path != "/" and not path.startswith("#"):
                    endpoints.append(path)
    return list(dict.fromkeys(endpoints))


def check_exposed_file(
    response: CapturedResponse,
    baseline: Optional[CapturedResponse],
) -> List[CandidateFinding]:
    """
    Pure check evaluating whether an allow-listed path is genuinely exposed.
    Guards against soft-404/SPA responses and requires meaningful content verification.
    """
    findings: List[CandidateFinding] = []
    url = response.url
    body = response.body or ""

    if is_soft_404(response, baseline):
        return []

    # 1. Directory Listing Signature
    if DIRECTORY_LISTING_REGEX.search(body):
        findings.append(
            CandidateFinding(
                title=f"Directory Listing Enabled on '{response.url}'",
                category="exposed_files",
                description=f"Web server directory listing is enabled at '{response.url}', exposing internal file names and folder structures.",
                severity=FindingSeverity.MEDIUM,
                affected_url=url,
                wstg_id="WSTG-CONF-04",
                owasp_top10="A05:2021-Security Misconfiguration",
                cwe="CWE-548",
                remediation="Disable directory browsing/indexing in web server configuration (e.g. 'Options -Indexes' in Apache).",
                evidence_label="Directory Listing Signature",
                evidence_content=response.raw_text[:2000],
            )
        )
        return findings

    # 2. .git/HEAD
    if url.endswith("/.git/HEAD"):
        if body.startswith("ref:") or re.match(r"^[0-9a-f]{40}", body.strip()):
            findings.append(
                CandidateFinding(
                    title="Exposed Git Repository Metadata (/.git/HEAD)",
                    category="exposed_files",
                    description=f"Publicly accessible Git repository metadata found at '{url}'. Attackers can dump source code and commit history.",
                    severity=FindingSeverity.HIGH,
                    affected_url=url,
                    wstg_id="WSTG-CONF-04",
                    owasp_top10="A05:2021-Security Misconfiguration",
                    cwe="CWE-538",
                    remediation="Restrict web server access to '.git' directories and never deploy the '.git' folder into production docroots.",
                    evidence_label="Git HEAD Content",
                    evidence_content=response.raw_text[:1000],
                )
            )
            return findings

    # 3. .env file
    if url.endswith("/.env"):
        if ENV_VAR_REGEX.search(body) or any(k in body for k in ("DATABASE_URL", "SECRET", "PASSWORD", "API_KEY")):
            findings.append(
                CandidateFinding(
                    title="Exposed Environment Configuration File (/.env)",
                    category="exposed_files",
                    description=f"Production environment file accessible at '{url}'. Contains plaintext configuration parameters and potential secrets.",
                    severity=FindingSeverity.CRITICAL,
                    affected_url=url,
                    wstg_id="WSTG-CONF-04",
                    owasp_top10="A05:2021-Security Misconfiguration",
                    cwe="CWE-552",
                    remediation="Block access to '.env' files in web server rules and move sensitive configuration outside web root.",
                    evidence_label="Environment File Content",
                    evidence_content=response.raw_text[:1000],
                )
            )
            return findings

    # 4. .DS_Store
    if url.endswith("/.DS_Store"):
        if "Bud1" in body or body.startswith("\x00\x00\x00\x01"):
            findings.append(
                CandidateFinding(
                    title="Exposed macOS Metadata File (/.DS_Store)",
                    category="exposed_files",
                    description=f"macOS directory attribute metadata file accessible at '{url}', leaking hidden file names.",
                    severity=FindingSeverity.LOW,
                    affected_url=url,
                    wstg_id="WSTG-CONF-04",
                    owasp_top10="A05:2021-Security Misconfiguration",
                    cwe="CWE-538",
                    remediation="Remove .DS_Store files from web servers and configure server rules to deny access to hidden files.",
                    evidence_label="DS_Store Artifact",
                    evidence_content=response.raw_text[:500],
                )
            )
            return findings

    # 5. phpinfo.php
    if url.endswith("/phpinfo.php"):
        if "<title>phpinfo()" in body or "PHP Version " in body:
            findings.append(
                CandidateFinding(
                    title="Exposed PHP Info Diagnostic Page (/phpinfo.php)",
                    category="exposed_files",
                    description=f"Diagnostic phpinfo() output accessible at '{url}', disclosing exact server modules, PHP version, and environment variables.",
                    severity=FindingSeverity.MEDIUM,
                    affected_url=url,
                    wstg_id="WSTG-INFO-02",
                    owasp_top10="A05:2021-Security Misconfiguration",
                    cwe="CWE-200",
                    remediation="Remove diagnostic PHP files from publicly reachable docroots.",
                    evidence_label="phpinfo Output",
                    evidence_content=response.raw_text[:1500],
                )
            )
            return findings

    # 6. server-status
    if url.endswith("/server-status"):
        if "Apache Server Status" in body or "Server Version:" in body:
            findings.append(
                CandidateFinding(
                    title="Exposed Apache Server Status Page (/server-status)",
                    category="exposed_files",
                    description=f"Apache status handler accessible at '{url}', leaking live requests and client IP addresses.",
                    severity=FindingSeverity.MEDIUM,
                    affected_url=url,
                    wstg_id="WSTG-INFO-02",
                    owasp_top10="A05:2021-Security Misconfiguration",
                    cwe="CWE-200",
                    remediation="Restrict access to '/server-status' to localhost or trusted internal administration networks.",
                    evidence_label="Server Status Content",
                    evidence_content=response.raw_text[:1500],
                )
            )
            return findings

    # 7. package.json
    if url.endswith("/package.json"):
        if ('"name"' in body and '"version"' in body) or '"dependencies"' in body:
            findings.append(
                CandidateFinding(
                    title="Exposed Node.js Package Manifest (/package.json)",
                    category="exposed_files",
                    description=f"Node.js package.json file exposed at '{url}', disclosing application dependencies and versions.",
                    severity=FindingSeverity.LOW,
                    affected_url=url,
                    wstg_id="WSTG-CONF-04",
                    owasp_top10="A05:2021-Security Misconfiguration",
                    cwe="CWE-538",
                    remediation="Do not serve repository root files. Host only compiled client build artifacts.",
                    evidence_label="package.json Excerpt",
                    evidence_content=response.raw_text[:1000],
                )
            )
            return findings

    # 8. Swagger / API docs
    if url.endswith("/swagger.json") or url.endswith("/api-docs"):
        if '"swagger"' in body or '"openapi"' in body or "Swagger UI" in body:
            findings.append(
                CandidateFinding(
                    title="Exposed Interactive API Documentation",
                    category="exposed_files",
                    description=f"Publicly accessible API schema / swagger documentation discovered at '{url}'.",
                    severity=FindingSeverity.INFO,
                    affected_url=url,
                    wstg_id="WSTG-CONF-05",
                    owasp_top10="A05:2021-Security Misconfiguration",
                    cwe="CWE-200",
                    remediation="If APIs are private, enforce authentication before accessing API documentation.",
                    evidence_label="API Docs Signature",
                    evidence_content=response.raw_text[:1000],
                )
            )
            return findings

    # 9. Backup files / archives
    if url.endswith("/backup") or url.endswith("/backup.zip"):
        if body.startswith("PK\x03\x04") or "Content-Disposition" in (response.get_header("Content-Disposition") or ""):
            findings.append(
                CandidateFinding(
                    title="Exposed Backup Archive File",
                    category="exposed_files",
                    description=f"Possible backup zip archive file accessible at '{url}'.",
                    severity=FindingSeverity.HIGH,
                    affected_url=url,
                    wstg_id="WSTG-CONF-04",
                    owasp_top10="A05:2021-Security Misconfiguration",
                    cwe="CWE-530",
                    remediation="Delete backup archives from public directories and store backups in secure offsite repositories.",
                    evidence_label="Backup Archive Signature",
                    evidence_content=response.raw_text[:500],
                )
            )
            return findings

    # 10. robots.txt
    if url.endswith("/robots.txt") and response.status == 200:
        disallowed = parse_robots_txt(body)
        if disallowed:
            findings.append(
                CandidateFinding(
                    title="Robots.txt Discloses Sensitive Path Endpoints",
                    category="exposed_files",
                    description=f"The robots.txt file at '{url}' specifies {len(disallowed)} Disallow directives that reveal internal paths: {', '.join(disallowed[:5])}",
                    severity=FindingSeverity.INFO,
                    affected_url=url,
                    wstg_id="WSTG-CONF-05",
                    owasp_top10="A05:2021-Security Misconfiguration",
                    cwe="CWE-200",
                    remediation="Do not rely on robots.txt for access control. Protect sensitive endpoints with proper authentication and authorization.",
                    evidence_label="Robots.txt Content",
                    evidence_content=response.raw_text[:1500],
                )
            )

    return findings
