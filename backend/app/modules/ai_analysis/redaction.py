"""Deterministic sensitive data and credentials scrubbing engine.

Ensures no raw secrets, credentials, tokens, or untrusted instruction delimiters
leak to external LLM providers.
"""
import re
import xml.etree.ElementTree as ET
from typing import Dict, Any, Tuple, Optional
from pydantic import BaseModel

# Delimiters used to encapsulate untrusted scan and target data
DELIMITER_BEGIN = "<<<BEGIN_UNTRUSTED_DATA>>>"
DELIMITER_END = "<<<END_UNTRUSTED_DATA>>>"
DELIMITER_ALT = "=== UNTRUSTED DATA ==="


class RedactionReport(BaseModel):
    """Structured report tracking redactions per secret category."""
    auth_tokens: int = 0
    cookies: int = 0
    jwt_tokens: int = 0
    api_keys: int = 0
    private_keys: int = 0
    passwords: int = 0
    emails: int = 0
    url_credentials: int = 0
    internal_ips: int = 0
    truncated_items: int = 0
    total_redacted: int = 0
    original_chars: int = 0
    redacted_chars: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class RedactedText:
    """
    Type-safe wrapper guaranteeing that enclosed text has been scrubbed
    by the redaction engine. The LLM client strictly rejects unredacted strings.
    """
    def __init__(self, text: str, report: RedactionReport):
        if not isinstance(text, str):
            raise TypeError("RedactedText requires a string payload.")
        if not isinstance(report, RedactionReport):
            raise TypeError("RedactedText requires a valid RedactionReport.")
        self._text = text
        self._report = report

    @property
    def text(self) -> str:
        return self._text

    @property
    def report(self) -> RedactionReport:
        return self._report

    def __str__(self) -> str:
        return self._text

    def __repr__(self) -> str:
        return f"<RedactedText chars={len(self._text)} total_redacted={self._report.total_redacted}>"


# Known cookie attribute names to preserve
COOKIE_ATTRIBUTES = {
    "secure", "httponly", "samesite", "path", "domain", "expires",
    "max-age", "priority", "partitioned"
}


def neutralize_delimiters(text: str) -> str:
    """Neutralize delimiter markers inside raw content to prevent prompt injection escapes."""
    text = text.replace(DELIMITER_BEGIN, "[SANITIZED_DELIMITER_BEGIN]")
    text = text.replace(DELIMITER_END, "[SANITIZED_DELIMITER_END]")
    text = text.replace(DELIMITER_ALT, "[SANITIZED_DELIMITER]")
    return text


def _redact_cookies_in_line(line: str) -> Tuple[str, int]:
    """
    Redact cookie values while preserving cookie names and security attributes.
    Handles 'Set-Cookie: ...' and 'Cookie: ...'.
    """
    count = 0
    # 1. Set-Cookie header
    set_cookie_match = re.match(
        r"^(\s*(?:[<>]\s*)?Set-Cookie\s*:\s*)(.*)$", line, re.IGNORECASE
    )
    if set_cookie_match:
        prefix = set_cookie_match.group(1)
        rest = set_cookie_match.group(2)
        parts = rest.split(";")
        new_parts = []
        for i, part in enumerate(parts):
            part_stripped = part.strip()
            if "=" in part_stripped:
                name, val = part_stripped.split("=", 1)
                name_clean = name.strip()
                val_clean = val.strip()
                if i == 0 or name_clean.lower() not in COOKIE_ATTRIBUTES:
                    if val_clean != "[REDACTED_COOKIE_VALUE]":
                        new_parts.append(f"{name_clean}=[REDACTED_COOKIE_VALUE]")
                        count += 1
                    else:
                        new_parts.append(f"{name_clean}={val_clean}")
                else:
                    new_parts.append(part_stripped)
            else:
                new_parts.append(part_stripped)
        return prefix + "; ".join(new_parts), count

    # 2. Cookie header: Cookie: name1=val1; name2=val2
    cookie_match = re.match(
        r"^(\s*(?:[<>]\s*)?Cookie\s*:\s*)(.*)$", line, re.IGNORECASE
    )
    if cookie_match:
        prefix = cookie_match.group(1)
        rest = cookie_match.group(2)
        parts = rest.split(";")
        new_parts = []
        for part in parts:
            part_stripped = part.strip()
            if "=" in part_stripped:
                name, val = part_stripped.split("=", 1)
                name_clean = name.strip()
                val_clean = val.strip()
                if val_clean != "[REDACTED_COOKIE_VALUE]":
                    new_parts.append(f"{name_clean}=[REDACTED_COOKIE_VALUE]")
                    count += 1
                else:
                    new_parts.append(f"{name_clean}={val_clean}")
            else:
                new_parts.append(part_stripped)
        return prefix + "; ".join(new_parts), count

    return line, 0


def redact_text(
    raw_text: str,
    max_chars: Optional[int] = None,
    redact_internal_ips: bool = False,
) -> RedactedText:
    """
    Pure redaction function. Scrubs secrets, tokens, and credentials deterministically.
    Returns RedactedText instance containing redacted string and RedactionReport.
    """
    if raw_text is None:
        raw_text = ""

    original_length = len(raw_text)
    report = RedactionReport(original_chars=original_length)
    text = raw_text

    # 1. Private key blocks (RSA, EC, DSA, OPENSSH, etc.)
    pk_pattern = re.compile(
        r"-----BEGIN [A-Z0-9\-_ ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9\-_ ]*PRIVATE KEY-----"
    )
    pk_matches = pk_pattern.findall(text)
    if pk_matches:
        report.private_keys += len(pk_matches)
        text = pk_pattern.sub("[REDACTED_PRIVATE_KEY]", text)

    # 2. JWT Tokens (header.payload.signature)
    jwt_pattern = re.compile(
        r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"
    )
    jwt_matches = jwt_pattern.findall(text)
    if jwt_matches:
        report.jwt_tokens += len(jwt_matches)
        text = jwt_pattern.sub("[REDACTED_JWT]", text)

    # 3. Known API Keys and High-Entropy Provider Tokens
    # AWS Access Key ID
    aws_pattern = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
    aws_matches = aws_pattern.findall(text)
    if aws_matches:
        report.api_keys += len(aws_matches)
        text = aws_pattern.sub("[REDACTED_AWS_KEY]", text)

    # OpenAI / Claude API keys
    sk_pattern = re.compile(r"\bsk-[a-zA-Z0-9_-]{20,}\b")
    sk_matches = sk_pattern.findall(text)
    if sk_matches:
        report.api_keys += len(sk_matches)
        text = sk_pattern.sub("[REDACTED_API_KEY]", text)

    # Google API Key
    aiza_pattern = re.compile(r"\bAIza[0-9A-Za-z\-_]{30,45}\b")
    aiza_matches = aiza_pattern.findall(text)
    if aiza_matches:
        report.api_keys += len(aiza_matches)
        text = aiza_pattern.sub("[REDACTED_GEMINI_KEY]", text)

    # GitHub personal access tokens
    gh_pattern = re.compile(r"\bgh[pousr]_[0-9a-zA-Z]{36,255}\b")
    gh_matches = gh_pattern.findall(text)
    if gh_matches:
        report.api_keys += len(gh_matches)
        text = gh_pattern.sub("[REDACTED_GITHUB_TOKEN]", text)

    # Generic api_key / secret_key / auth_token key-value patterns
    generic_key_pattern = re.compile(
        r"(?i)\b((?:api[_-]?key|access[_-]?token|auth(?:entication)?[_-]?token|token|secret[_-]?key)\s*[:=]\s*['\"]?)([^'\"\s&,;]+)(['\"]?)"
    )
    def _replace_generic_key(m):
        if "[REDACTED_" in m.group(2):
            return m.group(0)
        report.api_keys += 1
        return f"{m.group(1)}[REDACTED_API_KEY]{m.group(3)}"
    text = generic_key_pattern.sub(_replace_generic_key, text)

    # 4. Authorization Header (Bearer, Basic)
    auth_bearer_pattern = re.compile(r"(?i)(\bAuthorization\s*:\s*Bearer\s+)([^\r\n,;]+)")
    def _replace_bearer(m):
        val = m.group(2).strip()
        if val in ("[REDACTED_BEARER_TOKEN]", "[REDACTED_JWT]"):
            return m.group(0)
        report.auth_tokens += 1
        return f"{m.group(1)}[REDACTED_BEARER_TOKEN]"
    text = auth_bearer_pattern.sub(_replace_bearer, text)

    auth_basic_pattern = re.compile(r"(?i)(\bAuthorization\s*:\s*Basic\s+)([^\r\n,;]+)")
    def _replace_basic(m):
        val = m.group(2).strip()
        if val == "[REDACTED_BASIC_AUTH]":
            return m.group(0)
        report.auth_tokens += 1
        return f"{m.group(1)}[REDACTED_BASIC_AUTH]"
    text = auth_basic_pattern.sub(_replace_basic, text)

    auth_header_pattern = re.compile(
        r"(?im)^(\s*(?:[<>]\s*)?Authorization\s*:\s*)([^\r\n]*)"
    )
    def _replace_auth_header(m):
        value = m.group(2).strip()
        if not value or "[REDACTED_" in value:
            return m.group(0)
        report.auth_tokens += 1
        return f"{m.group(1)}[REDACTED_AUTH_HEADER]"
    text = auth_header_pattern.sub(_replace_auth_header, text)

    # 5. Cookies & Set-Cookie headers line by line
    if "cookie" in text.lower():
        lines = text.split("\n")
        new_lines = []
        for line in lines:
            if "cookie" in line.lower():
                redacted_line, count = _redact_cookies_in_line(line)
                report.cookies += count
                new_lines.append(redacted_line)
            else:
                new_lines.append(line)
        text = "\n".join(new_lines)

    # 6. Basic-auth credentials in URLs (e.g. https://user:pass@example.com)
    url_cred_pattern = re.compile(r"(https?://)([a-zA-Z0-9_\-\.%]+):([^@\s/]+)@")
    def _replace_url_cred(m):
        if "[REDACTED_" in m.group(2) or "[REDACTED_" in m.group(3):
            return m.group(0)
        report.url_credentials += 1
        return f"{m.group(1)}[REDACTED_USER]:[REDACTED_PASS]@"
    text = url_cred_pattern.sub(_replace_url_cred, text)

    # 7. Passwords in parameters / form bodies / query strings
    pwd_param_pattern = re.compile(r"(?i)\b((?:password|passwd|pwd|secret)\s*[:=]\s*['\"]?)([^'\"&\s,;]+)(['\"]?)")
    def _replace_pwd(m):
        val = m.group(2).strip()
        if "[REDACTED_" in val:
            return m.group(0)
        report.passwords += 1
        return f"{m.group(1)}[REDACTED_PASSWORD]{m.group(3)}"
    text = pwd_param_pattern.sub(_replace_pwd, text)

    # JSON password field: "password": "value"
    json_pwd_pattern = re.compile(r"(?i)(\"(?:password|passwd|pwd|secret)\"\s*:\s*\")[^\"]+(\")")
    def _replace_json_pwd(m):
        if "[REDACTED_" in m.group(0):
            return m.group(0)
        report.passwords += 1
        return f"{m.group(1)}[REDACTED_PASSWORD]{m.group(2)}"
    text = json_pwd_pattern.sub(_replace_json_pwd, text)

    # 8. Email addresses
    email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    email_matches = email_pattern.findall(text)
    if email_matches:
        report.emails += len(email_matches)
        text = email_pattern.sub("[REDACTED_EMAIL]", text)

    # 9. Internal IPs (optional)
    if redact_internal_ips:
        ip_pattern = re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")
        ip_matches = ip_pattern.findall(text)
        if ip_matches:
            report.internal_ips += len(ip_matches)
            text = ip_pattern.sub("[REDACTED_INTERNAL_IP]", text)

    # 10. Neutralize injection delimiters
    text = neutralize_delimiters(text)

    # 11. Truncation if max_chars is specified
    if max_chars is not None and len(text) > max_chars:
        text = text[:max_chars] + "\n[TRUNCATED: Exceeded max allowed length]"
        report.truncated_items += 1

    report.redacted_chars = len(text)
    report.total_redacted = (
        report.auth_tokens
        + report.cookies
        + report.jwt_tokens
        + report.api_keys
        + report.private_keys
        + report.passwords
        + report.emails
        + report.url_credentials
        + report.internal_ips
    )

    return RedactedText(text=text, report=report)


def _summarize_nmap_xml(raw_text: str) -> Optional[str]:
    """Extract host, port, and service facts from Nmap XML without response payloads."""
    try:
        root = ET.fromstring(raw_text)
    except ET.ParseError:
        return None

    if root.tag != "nmaprun":
        return None

    lines = ["Nmap scan summary:"]
    for host in root.findall("host"):
        addresses = [
            f"{item.get('addrtype', 'address')}={item.get('addr', '')}"
            for item in host.findall("address")
        ]
        if addresses:
            lines.append(f"Host: {', '.join(addresses)}")
        status = host.find("status")
        if status is not None:
            lines.append(f"Host status: {status.get('state', 'unknown')}")
        for port in host.findall("./ports/port"):
            state = port.find("state")
            service = port.find("service")
            state_name = state.get("state", "unknown") if state is not None else "unknown"
            service_name = service.get("name", "unknown") if service is not None else "unknown"
            version = ""
            if service is not None:
                version = " ".join(
                    part for part in (
                        service.get("product", ""),
                        service.get("version", ""),
                    ) if part
                )
            lines.append(
                f"Port {port.get('portid', '?')}/{port.get('protocol', '?')}: "
                f"{state_name}; service={service_name}"
                + (f" {version}" if version else "")
            )
    return "\n".join(lines)


def _summarize_scan_text(text: str, max_chars: int) -> str:
    """Keep scan headings and high-signal probe, header, port, and service lines."""
    nmap_summary = _summarize_nmap_xml(text)
    if nmap_summary is not None:
        return nmap_summary[:max_chars]

    relevant = re.compile(
        r"(?i)(?:^===|^\[|^\$\s+dig\b|^\S+\s+\d+\s+IN\s+(?:A|AAAA|NS|MX|TXT|CNAME|PTR)\s+|"
        r"^>\s*(?:GET|HEAD|OPTIONS|Host:)|^<\s*HTTP/|^HTTP/\S+\s+\d{3}|"
        r"^\s*(?:<\s*)?(?:server|content-type|content-length|location|"
        r"strict-transport-security|content-security-policy|x-frame-options|"
        r"x-content-type-options|access-control-allow-[\w-]+|set-cookie|"
        r"www-authenticate|allow|connection|date)\s*:|"
        r"\b(?:port|service|TLS|SSL|certificate|curl error|probe result|"
        r"No (?:A|AAAA|NS|MX|TXT|PTR) records returned|"
        r"error|exception|stack trace|not found|forbidden|unauthorized|"
        r"index\.html|source map|robots\.txt)\b)"
    )
    selected = []
    in_response_headers = False
    awaiting_body = False
    body_lines = 0
    for line in text.splitlines():
        candidate = line.strip()
        if not candidate:
            continue

        if candidate.startswith(("===", "[")) or candidate.startswith("> "):
            in_response_headers = False
            awaiting_body = False
            body_lines = 0

        if candidate.startswith("< HTTP/"):
            in_response_headers = True
            awaiting_body = False
            body_lines = 0
        elif in_response_headers:
            if candidate.startswith("< ") and ":" in candidate:
                if relevant.search(candidate):
                    selected.append(candidate[:800])
                continue
            in_response_headers = False
            awaiting_body = True

        if awaiting_body:
            selected.append(f"Body excerpt: {candidate[:300]}")
            body_lines += 1
            if body_lines >= 2:
                awaiting_body = False
            continue

        if relevant.search(candidate):
            selected.append(candidate[:800])
        if sum(map(len, selected)) >= max_chars:
            break

    summary = "\n".join(selected)
    if not summary:
        summary = text[:max_chars]
    if len(summary) > max_chars:
        summary = summary[:max_chars]
    if len(text) > len(summary):
        suffix = f"\n[Summarized scan output; {len(text) - len(summary)} characters omitted]"
        summary = summary[: max(0, max_chars - len(suffix))] + suffix
    return summary


def redact_scan_output(
    raw_text: str,
    max_chars: int,
    redact_internal_ips: bool = False,
) -> RedactedText:
    """Redact complete scan output, then summarize it within the model input budget."""
    redacted = redact_text(raw_text, redact_internal_ips=redact_internal_ips)
    summary = _summarize_scan_text(redacted.text, max_chars)
    if summary == redacted.text:
        return redacted

    report = redacted.report.model_copy(
        update={
            "truncated_items": redacted.report.truncated_items + 1,
            "redacted_chars": len(summary),
        }
    )
    return RedactedText(summary, report)
