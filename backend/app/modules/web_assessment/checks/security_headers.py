import re
from typing import List, Dict, Any, Optional
from app.modules.findings import FindingSeverity
from app.modules.web_assessment.types import CapturedResponse, CandidateFinding


def check_security_headers(response: CapturedResponse) -> List[CandidateFinding]:
    """
    Pure check evaluating security headers on an HTTP response.
    OWASP WSTG: WSTG-CONF-07 (HTTP Strict Transport Security), WSTG-CRYP-01.
    OWASP Top 10: A05:2021-Security Misconfiguration.
    """
    findings: List[CandidateFinding] = []
    url = response.url
    is_https = url.lower().startswith("https://")

    # 1. Content-Security-Policy
    csp = response.get_header("Content-Security-Policy")
    if not csp:
        findings.append(
            CandidateFinding(
                title="Missing Content-Security-Policy Header",
                category="security_headers",
                description="The Content-Security-Policy (CSP) response header is missing. CSP helps prevent Cross-Site Scripting (XSS), clickjacking, and other code injection attacks.",
                severity=FindingSeverity.MEDIUM,
                affected_url=url,
                wstg_id="WSTG-CONF-07",
                owasp_top10="A05:2021-Security Misconfiguration",
                cwe="CWE-693",
                remediation="Define a Content-Security-Policy header restricting script, style, frame, and object sources (e.g., default-src 'self').",
                evidence_label="Response Headers (CSP Missing)",
                evidence_content=response.raw_text,
            )
        )
    else:
        # Check for unsafe directives
        lower_csp = csp.lower()
        if ("'unsafe-inline'" in lower_csp or "'unsafe-eval'" in lower_csp) and "nonce-" not in lower_csp and "sha256-" not in lower_csp:
            findings.append(
                CandidateFinding(
                    title="Weak Content-Security-Policy (Unsafe Directives)",
                    category="security_headers",
                    description=f"Content-Security-Policy allows 'unsafe-inline' or 'unsafe-eval' without nonces or hashes: {csp}",
                    severity=FindingSeverity.LOW,
                    affected_url=url,
                    wstg_id="WSTG-CONF-07",
                    owasp_top10="A05:2021-Security Misconfiguration",
                    cwe="CWE-693",
                    remediation="Remove 'unsafe-inline' and 'unsafe-eval' directives. Use cryptographic nonces or hashes for legitimate inline scripts.",
                    evidence_label="Weak CSP Value",
                    evidence_content=f"Content-Security-Policy: {csp}",
                )
            )

    # 2. X-Frame-Options (or frame-ancestors in CSP)
    xfo = response.get_header("X-Frame-Options")
    has_frame_ancestors = csp is not None and "frame-ancestors" in csp.lower()
    if not xfo and not has_frame_ancestors:
        findings.append(
            CandidateFinding(
                title="Missing Anti-Clickjacking Protection (X-Frame-Options)",
                category="security_headers",
                description="The response lacks both X-Frame-Options and CSP frame-ancestors directive, potentially permitting UI redressing / clickjacking attacks.",
                severity=FindingSeverity.LOW,
                affected_url=url,
                wstg_id="WSTG-CONF-07",
                owasp_top10="A05:2021-Security Misconfiguration",
                cwe="CWE-1021",
                remediation="Configure 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or specify 'frame-ancestors 'self'' in Content-Security-Policy.",
                evidence_label="Missing Clickjacking Defense",
                evidence_content=response.raw_text,
            )
        )

    # 3. X-Content-Type-Options
    xcto = response.get_header("X-Content-Type-Options")
    if not xcto or xcto.lower().strip() != "nosniff":
        findings.append(
            CandidateFinding(
                title="Missing or Weak X-Content-Type-Options Header",
                category="security_headers",
                description="The X-Content-Type-Options header is absent or not set to 'nosniff'. Browsers may attempt to MIME-sniff the response body, leading to XSS vulnerabilities.",
                severity=FindingSeverity.LOW,
                affected_url=url,
                wstg_id="WSTG-CONF-07",
                owasp_top10="A05:2021-Security Misconfiguration",
                cwe="CWE-693",
                remediation="Add 'X-Content-Type-Options: nosniff' to all HTTP responses.",
                evidence_label="Missing X-Content-Type-Options",
                evidence_content=response.raw_text,
            )
        )

    # 4. Referrer-Policy
    ref_pol = response.get_header("Referrer-Policy")
    if not ref_pol or ref_pol.lower().strip() == "unsafe-url":
        findings.append(
            CandidateFinding(
                title="Missing or Insecure Referrer-Policy Header",
                category="security_headers",
                description=f"The Referrer-Policy header is {'missing' if not ref_pol else 'set to unsafe-url'}. URLs containing sensitive tokens or query parameters might leak to third parties.",
                severity=FindingSeverity.INFO,
                affected_url=url,
                wstg_id="WSTG-CONF-07",
                owasp_top10="A05:2021-Security Misconfiguration",
                cwe="CWE-693",
                remediation="Configure 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
                evidence_label="Referrer Policy Inspection",
                evidence_content=response.raw_text,
            )
        )

    # 5. Permissions-Policy
    perm_pol = response.get_header("Permissions-Policy")
    if not perm_pol:
        findings.append(
            CandidateFinding(
                title="Missing Permissions-Policy Header",
                category="security_headers",
                description="The Permissions-Policy header is absent. Restricting powerful browser APIs (e.g. camera, microphone, geolocation) reduces attack surface.",
                severity=FindingSeverity.INFO,
                affected_url=url,
                wstg_id="WSTG-CONF-07",
                owasp_top10="A05:2021-Security Misconfiguration",
                cwe="CWE-693",
                remediation="Set a Permissions-Policy header disabling unused browser capabilities (e.g. 'geolocation=(), camera=(), microphone=()').",
                evidence_label="Missing Permissions-Policy",
                evidence_content=response.raw_text,
            )
        )

    # 6. Strict-Transport-Security (only applicable on HTTPS)
    if is_https:
        hsts = response.get_header("Strict-Transport-Security")
        if not hsts:
            findings.append(
                CandidateFinding(
                    title="Missing Strict-Transport-Security (HSTS) Header",
                    category="security_headers",
                    description="The HTTPS response does not include an HSTS header, allowing man-in-the-middle attackers to perform SSL-stripping attacks on subsequent connections.",
                    severity=FindingSeverity.LOW,
                    affected_url=url,
                    wstg_id="WSTG-CONF-07",
                    owasp_top10="A05:2021-Security Misconfiguration",
                    cwe="CWE-319",
                    remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses.",
                    evidence_label="Missing HSTS Header",
                    evidence_content=response.raw_text,
                )
            )
        else:
            match = re.search(r"max-age=(\d+)", hsts.lower())
            if match and int(match.group(1)) < 15552000:  # < 180 days
                findings.append(
                    CandidateFinding(
                        title="Weak Strict-Transport-Security Max-Age",
                        category="security_headers",
                        description=f"HSTS header specifies max-age of {match.group(1)} seconds, which is less than the recommended 180 days (15552000 seconds).",
                        severity=FindingSeverity.LOW,
                        affected_url=url,
                        wstg_id="WSTG-CONF-07",
                        owasp_top10="A05:2021-Security Misconfiguration",
                        cwe="CWE-319",
                        remediation="Increase the HSTS max-age to at least 31536000 (1 year).",
                        evidence_label="Weak HSTS Header",
                        evidence_content=f"Strict-Transport-Security: {hsts}",
                    )
                )

    return findings


def check_cors_configuration(
    response: CapturedResponse,
    origin_tested: Optional[str] = None,
) -> List[CandidateFinding]:
    """Check for overly permissive or dynamically reflected CORS headers."""
    findings: List[CandidateFinding] = []
    allow_origin = response.get_header("Access-Control-Allow-Origin")
    allow_cred = response.get_header("Access-Control-Allow-Credentials")
    is_cred_true = (allow_cred or "").lower() == "true"

    if allow_origin and allow_origin.strip() == "*" and is_cred_true:
        findings.append(
            CandidateFinding(
                title="Insecure Permissive CORS (Wildcard with Credentials)",
                category="security_headers",
                description="The server specifies 'Access-Control-Allow-Origin: *' combined with 'Access-Control-Allow-Credentials: true', exposing authenticated resources to any origin.",
                severity=FindingSeverity.HIGH,
                affected_url=response.url,
                wstg_id="WSTG-CONF-07",
                owasp_top10="A05:2021-Security Misconfiguration",
                cwe="CWE-942",
                remediation="Do not combine wildcard origins with credentials. Use an explicit allow-list of trusted origins.",
                evidence_label="Permissive CORS Headers",
                evidence_content=f"Access-Control-Allow-Origin: {allow_origin}\nAccess-Control-Allow-Credentials: {allow_cred}",
            )
        )
    elif allow_origin and allow_origin.strip() == "*":
        findings.append(
            CandidateFinding(
                title="Wildcard Access-Control-Allow-Origin",
                category="security_headers",
                description="The response allows requests from any origin with 'Access-Control-Allow-Origin: *'.",
                severity=FindingSeverity.LOW,
                affected_url=response.url,
                wstg_id="WSTG-CONF-07",
                owasp_top10="A05:2021-Security Misconfiguration",
                cwe="CWE-942",
                remediation="Restrict Access-Control-Allow-Origin to the origins that require access.",
                evidence_label="Wildcard CORS Response Header",
                evidence_content=f"Access-Control-Allow-Origin: {allow_origin}",
            )
        )

    if origin_tested and allow_origin and allow_origin.strip() == origin_tested and is_cred_true:
        findings.append(
            CandidateFinding(
                title="Arbitrary CORS Origin Reflection with Credentials",
                category="security_headers",
                description=f"The server reflects arbitrary requested Origin '{origin_tested}' in Access-Control-Allow-Origin while enabling credentials.",
                severity=FindingSeverity.HIGH,
                affected_url=response.url,
                wstg_id="WSTG-CONF-07",
                owasp_top10="A05:2021-Security Misconfiguration",
                cwe="CWE-942",
                remediation="Validate Origin against a strict server-side allow-list before reflecting it in CORS response headers.",
                evidence_label="Reflected CORS Origin",
                evidence_content=f"Request Origin: {origin_tested}\nAccess-Control-Allow-Origin: {allow_origin}\nAccess-Control-Allow-Credentials: {allow_cred}",
            )
        )

    return findings


def check_plain_http_target(target_url: str, https_available: bool) -> List[CandidateFinding]:
    """Flag target served over plain HTTP with no HTTPS available."""
    findings: List[CandidateFinding] = []
    if target_url.lower().startswith("http://") and not https_available:
        findings.append(
            CandidateFinding(
                title="Target Served Over Plain HTTP (No HTTPS Available)",
                category="security_headers",
                description=f"The application at '{target_url}' is served over plain unencrypted HTTP and does not offer HTTPS. Communications are exposed to eavesdropping and manipulation.",
                severity=FindingSeverity.MEDIUM,
                affected_url=target_url,
                wstg_id="WSTG-CRYP-01",
                owasp_top10="A02:2021-Cryptographic Failures",
                cwe="CWE-319",
                remediation="Obtain a valid TLS certificate and configure the web server to listen on HTTPS (port 443).",
                evidence_label="Plain HTTP Inspection",
                evidence_content=f"Target: {target_url}\nHTTPS Reachable: False",
            )
        )
    return findings


def check_http_to_https_redirect(
    http_response: CapturedResponse,
    https_available: bool,
) -> List[CandidateFinding]:
    """Check if plain HTTP automatically redirects to HTTPS when HTTPS is available."""
    findings: List[CandidateFinding] = []
    if http_response.url.lower().startswith("http://") and https_available:
        loc = http_response.get_header("Location") or ""
        is_redirect = http_response.status in (301, 302, 307, 308) and loc.lower().startswith("https://")
        if not is_redirect:
            findings.append(
                CandidateFinding(
                    title="Missing HTTP to HTTPS Redirect",
                    category="security_headers",
                    description=f"HTTPS is available, but plain HTTP requests to '{http_response.url}' are not redirected to HTTPS (Status: {http_response.status}).",
                    severity=FindingSeverity.LOW,
                    affected_url=http_response.url,
                    wstg_id="WSTG-CONF-07",
                    owasp_top10="A05:2021-Security Misconfiguration",
                    cwe="CWE-319",
                    remediation="Configure the web server to return a 301 Permanent Redirect to HTTPS for all plain HTTP connections.",
                    evidence_label="Plain HTTP Response Without Redirect",
                    evidence_content=http_response.raw_text,
                )
            )
    return findings


def check_tls_configuration(tls_info: Dict[str, Any], target_host: str) -> List[CandidateFinding]:
    """Pure check assessing TLS certificate and protocol validity from gathered TLS metadata."""
    findings: List[CandidateFinding] = []
    affected_url = f"https://{target_host}"

    # 1. Deprecated protocols
    deprecated = [p for p in tls_info.get("accepted_protocols", []) if p in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")]
    if deprecated:
        findings.append(
            CandidateFinding(
                title=f"Deprecated TLS Protocols Supported ({', '.join(deprecated)})",
                category="security_headers",
                description=f"Target server accepts connections using deprecated SSL/TLS protocols ({', '.join(deprecated)}), vulnerable to BEAST, POODLE, or weak cryptographic ciphers.",
                severity=FindingSeverity.MEDIUM,
                affected_url=affected_url,
                wstg_id="WSTG-CRYP-01",
                owasp_top10="A02:2021-Cryptographic Failures",
                cwe="CWE-326",
                remediation="Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 in web server configuration. Enforce TLS 1.2 and TLS 1.3 only.",
                evidence_label="Supported Protocols",
                evidence_content=f"Accepted protocols: {tls_info.get('accepted_protocols')}",
            )
        )

    # 2. Certificate expired
    if tls_info.get("is_expired"):
        findings.append(
            CandidateFinding(
                title="Expired TLS Certificate",
                category="security_headers",
                description=f"The TLS certificate for '{target_host}' expired on {tls_info.get('not_after')}.",
                severity=FindingSeverity.HIGH,
                affected_url=affected_url,
                wstg_id="WSTG-CRYP-01",
                owasp_top10="A02:2021-Cryptographic Failures",
                cwe="CWE-298",
                remediation="Renew and install a valid TLS certificate from a trusted Certificate Authority.",
                evidence_label="Expired Certificate Details",
                evidence_content=f"Subject: {tls_info.get('subject')}\nNot After: {tls_info.get('not_after')}",
            )
        )

    # 3. Self-signed or untrusted
    if tls_info.get("is_self_signed"):
        findings.append(
            CandidateFinding(
                title="Self-Signed or Untrusted TLS Certificate",
                category="security_headers",
                description=f"The certificate presented by '{target_host}' is self-signed or not signed by a recognized Certificate Authority.",
                severity=FindingSeverity.MEDIUM,
                affected_url=affected_url,
                wstg_id="WSTG-CRYP-01",
                owasp_top10="A02:2021-Cryptographic Failures",
                cwe="CWE-295",
                remediation="Replace self-signed certificates with certificates issued by a publicly trusted CA (e.g. Let's Encrypt).",
                evidence_label="Certificate Issuer",
                evidence_content=f"Issuer: {tls_info.get('issuer')}\nSubject: {tls_info.get('subject')}",
            )
        )

    # 4. Hostname mismatch
    if tls_info.get("hostname_mismatch"):
        findings.append(
            CandidateFinding(
                title="TLS Certificate Hostname Mismatch",
                category="security_headers",
                description=f"The certificate Common Name / Subject Alternative Names ({tls_info.get('san', [])}) do not match the target hostname '{target_host}'.",
                severity=FindingSeverity.HIGH,
                affected_url=affected_url,
                wstg_id="WSTG-CRYP-01",
                owasp_top10="A02:2021-Cryptographic Failures",
                cwe="CWE-297",
                remediation="Reissue the TLS certificate including '{target_host}' in the Subject Alternative Name (SAN) extension.",
                evidence_label="Hostname Mismatch Details",
                evidence_content=f"Target Host: {target_host}\nSANs: {tls_info.get('san')}\nCommon Name: {tls_info.get('common_name')}",
            )
        )

    return findings
