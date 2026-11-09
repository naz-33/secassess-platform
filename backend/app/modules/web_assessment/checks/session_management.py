import re
from typing import List, Dict, Optional, Tuple
from app.modules.findings import FindingSeverity
from app.modules.web_assessment.types import CapturedResponse, CandidateFinding

SESSION_COOKIE_NAMES = {
    "session",
    "sessionid",
    "sess",
    "sid",
    "jsessionid",
    "phpsessid",
    "aspsessionid",
    "connect.sid",
    "token",
    "auth_token",
    "jwt",
    "auth",
}


def mask_cookie_value(value: str) -> str:
    """Mask cookie values for display summary fields."""
    if not value:
        return ""
    if len(value) <= 6:
        return "***"
    return f"{value[:3]}...{value[-3:]}"


def parse_set_cookie(header_value: str) -> Tuple[str, str, Dict[str, Optional[str]]]:
    """Parse a Set-Cookie header into (cookie_name, cookie_value, attributes_dict)."""
    parts = header_value.split(";")
    first_part = parts[0].strip()
    if "=" in first_part:
        cookie_name, cookie_value = first_part.split("=", 1)
        cookie_name = cookie_name.strip()
        cookie_value = cookie_value.strip()
    else:
        cookie_name = first_part
        cookie_value = ""

    attributes: Dict[str, Optional[str]] = {}
    for part in parts[1:]:
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            attributes[k.strip().lower()] = v.strip()
        else:
            attributes[part.lower()] = None

    return cookie_name, cookie_value, attributes


def check_cookie_attributes(response: CapturedResponse) -> List[CandidateFinding]:
    """
    Check all Set-Cookie headers in the captured response for security attributes.
    OWASP WSTG: WSTG-SESS-02 (Cookie Attributes), WSTG-SESS-01 (Session Management Schema).
    OWASP Top 10: A07:2021-Identification and Authentication Failures.
    """
    findings: List[CandidateFinding] = []
    url = response.url
    is_https = url.lower().startswith("https://")
    set_cookies = response.get_headers("Set-Cookie")

    for raw_cookie in set_cookies:
        name, value, attrs = parse_set_cookie(raw_cookie)
        masked_val = mask_cookie_value(value)
        is_session_like = name.lower() in SESSION_COOKIE_NAMES or "sess" in name.lower() or "auth" in name.lower()

        # 1. Missing HttpOnly
        if "httponly" not in attrs:
            findings.append(
                CandidateFinding(
                    title=f"Cookie Missing HttpOnly Flag ('{name}')",
                    category="session_management",
                    description=(
                        f"The cookie '{name}' (value: {masked_val}) is set without the 'HttpOnly' flag. "
                        "Client-side scripts can access this cookie via document.cookie, making it vulnerable to XSS theft."
                    ),
                    severity=FindingSeverity.MEDIUM if is_session_like else FindingSeverity.LOW,
                    affected_url=url,
                    wstg_id="WSTG-SESS-02",
                    owasp_top10="A07:2021-Identification and Authentication Failures",
                    cwe="CWE-1004",
                    remediation=f"Add the 'HttpOnly' directive to Set-Cookie for '{name}'.",
                    evidence_label=f"Cookie: {name}",
                    evidence_content=f"Set-Cookie: {raw_cookie}",
                )
            )

        # 2. Missing Secure flag (on HTTPS)
        if is_https and "secure" not in attrs:
            findings.append(
                CandidateFinding(
                    title=f"Cookie Missing Secure Flag ('{name}')",
                    category="session_management",
                    description=(
                        f"The cookie '{name}' is transmitted over HTTPS but lacks the 'Secure' attribute. "
                        "Browsers may send this cookie in subsequent unencrypted HTTP requests."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    affected_url=url,
                    wstg_id="WSTG-SESS-02",
                    owasp_top10="A07:2021-Identification and Authentication Failures",
                    cwe="CWE-614",
                    remediation=f"Add the 'Secure' directive to Set-Cookie for '{name}'.",
                    evidence_label=f"Cookie: {name}",
                    evidence_content=f"Set-Cookie: {raw_cookie}",
                )
            )

        # 3. Missing or weak SameSite attribute
        samesite = attrs.get("samesite")
        if samesite is None and "samesite" not in attrs:
            findings.append(
                CandidateFinding(
                    title=f"Cookie Missing SameSite Attribute ('{name}')",
                    category="session_management",
                    description=(
                        f"The cookie '{name}' does not specify a 'SameSite' attribute. "
                        "Without SameSite (Lax or Strict), the cookie may be submitted in cross-site requests, increasing CSRF exposure."
                    ),
                    severity=FindingSeverity.LOW,
                    affected_url=url,
                    wstg_id="WSTG-SESS-02",
                    owasp_top10="A07:2021-Identification and Authentication Failures",
                    cwe="CWE-1275",
                    remediation=f"Set 'SameSite=Lax' or 'SameSite=Strict' on the '{name}' cookie.",
                    evidence_label=f"Cookie: {name}",
                    evidence_content=f"Set-Cookie: {raw_cookie}",
                )
            )
        elif samesite and samesite.lower() == "none" and "secure" not in attrs:
            findings.append(
                CandidateFinding(
                    title=f"Insecure SameSite=None Without Secure Attribute ('{name}')",
                    category="session_management",
                    description=f"Cookie '{name}' specifies 'SameSite=None' without the 'Secure' flag, which modern browsers reject or transmit insecurely.",
                    severity=FindingSeverity.MEDIUM,
                    affected_url=url,
                    wstg_id="WSTG-SESS-02",
                    owasp_top10="A07:2021-Identification and Authentication Failures",
                    cwe="CWE-1275",
                    remediation=f"Always include 'Secure' when 'SameSite=None' is configured for '{name}'.",
                    evidence_label=f"Cookie: {name}",
                    evidence_content=f"Set-Cookie: {raw_cookie}",
                )
            )

        # 4. Overly long expiry (> 1 year)
        max_age = attrs.get("max-age")
        if max_age:
            try:
                seconds = int(max_age)
                if seconds > 31536000:  # > 365 days
                    findings.append(
                        CandidateFinding(
                            title=f"Cookie With Excessive Expiration Lifetime ('{name}')",
                            category="session_management",
                            description=f"Cookie '{name}' sets Max-Age={seconds} seconds (>{seconds // 86400} days). Persistent sessions expand the window of opportunity for token theft.",
                            severity=FindingSeverity.LOW,
                            affected_url=url,
                            wstg_id="WSTG-SESS-02",
                            owasp_top10="A07:2021-Identification and Authentication Failures",
                            cwe="CWE-613",
                            remediation="Set session cookie lifetimes to a reasonable operational period (e.g., hours to days) and rotate session keys upon logout.",
                            evidence_label=f"Cookie: {name}",
                            evidence_content=f"Set-Cookie: {raw_cookie}",
                        )
                    )
            except ValueError:
                pass

        # 5. Predictable or short session identifier
        if is_session_like and value:
            # Length check or purely numeric
            is_pure_digit = value.isdigit()
            is_too_short = len(value) < 16
            if is_pure_digit or is_too_short:
                findings.append(
                    CandidateFinding(
                        title=f"Weak or Predictable Session Identifier ('{name}')",
                        category="session_management",
                        description=(
                            f"The session identifier cookie '{name}' appears short ({len(value)} chars) or numeric "
                            f"(masked value: {masked_val}), suggesting insufficient entropy (< 128 bits) vulnerable to brute force."
                        ),
                        severity=FindingSeverity.MEDIUM,
                        affected_url=url,
                        wstg_id="WSTG-SESS-01",
                        owasp_top10="A07:2021-Identification and Authentication Failures",
                        cwe="CWE-384",
                        remediation="Generate cryptographically secure pseudo-random session identifiers with at least 128 bits of entropy (e.g. 32 hexadecimal or base64 characters).",
                        evidence_label=f"Session Cookie Entropy: {name}",
                        evidence_content=f"Set-Cookie: {raw_cookie}",
                    )
                )

    return findings


def check_session_fixation(
    pre_auth_cookie: Optional[str],
    post_auth_cookie: Optional[str],
    login_url: str,
) -> List[CandidateFinding]:
    """Flag when a session identifier remains identical before and after authentication."""
    findings: List[CandidateFinding] = []
    if pre_auth_cookie and post_auth_cookie and pre_auth_cookie == post_auth_cookie:
        findings.append(
            CandidateFinding(
                title="Session Fixation Vulnerability Detected",
                category="session_management",
                description="The session identifier was not regenerated upon successful authentication. Attackers can fixate a session ID before user login and hijack the session afterwards.",
                severity=FindingSeverity.HIGH,
                affected_url=login_url,
                wstg_id="WSTG-SESS-03",
                owasp_top10="A07:2021-Identification and Authentication Failures",
                cwe="CWE-384",
                remediation="Always invalidate the existing session and issue a newly generated session ID upon successful user authentication.",
                evidence_label="Session Fixation Evidence",
                evidence_content=f"Pre-Auth Session ID: {mask_cookie_value(pre_auth_cookie)}\nPost-Auth Session ID: {mask_cookie_value(post_auth_cookie)}",
            )
        )
    return findings
