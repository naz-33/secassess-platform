"""Curl HTTP response parser."""
import re
import urllib.parse
from typing import List, Tuple

from app.modules.web_assessment.types import CapturedResponse

DEFAULT_USER_AGENT = "SecAssess/1.0 Web Security Scanner"


def parse_raw_curl_response(
    raw_output: str,
    url: str,
    method: str,
    elapsed_ms: float,
    max_body_bytes: int = 200000,
    response_truncated: bool = False,
) -> CapturedResponse:
    """
    Parse curl's '-i' stdout output (headers + body) into a structured CapturedResponse.
    Preserves all header casing, order, and duplicates.
    """
    # Normalize CRLF
    normalized = raw_output.replace("\r\n", "\n")

    # If curl output contains 100 Continue blocks, find the final HTTP header section
    header_blocks = normalized.split("\n\n", 1)
    status_code = 200
    headers_list: List[Tuple[str, str]] = []
    body = ""
    truncated = response_truncated

    if len(header_blocks) >= 1:
        headers_section = header_blocks[0]
        body_section = header_blocks[1] if len(header_blocks) > 1 else ""

        # Check for multiple header blocks (e.g. HTTP/1.1 100 Continue)
        while headers_section.startswith("HTTP/") and "\nHTTP/" in body_section:
            next_header, remaining = body_section.split("\nHTTP/", 1)
            headers_section = "HTTP/" + remaining.split("\n\n", 1)[0]
            body_section = remaining.split("\n\n", 1)[1] if "\n\n" in remaining else ""

        lines = headers_section.split("\n")
        first_line = lines[0].strip()
        status_match = re.search(r"HTTP/\S+\s+(\d{3})", first_line)
        if status_match:
            status_code = int(status_match.group(1))

        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers_list.append((k.strip(), v.strip()))

        body = body_section
        if len(body.encode("utf-8", errors="ignore")) > max_body_bytes:
            body = body[:max_body_bytes]
            truncated = True

    # Assemble reconstructed transcript for human-readable summary/checks
    parsed_url = urllib.parse.urlsplit(url)
    host = parsed_url.netloc
    path = parsed_url.path or "/"
    if parsed_url.query:
        path = f"{path}?{parsed_url.query}"

    req_headers = f"> {method} {path} HTTP/1.1\n> Host: {host}\n> User-Agent: {DEFAULT_USER_AGENT}\n> Accept: */*\n"
    raw_transcript = f"{req_headers}\n< {first_line if 'first_line' in locals() else 'HTTP/1.1 ' + str(status_code)}\n"
    for k, v in headers_list:
        raw_transcript += f"< {k}: {v}\n"
    raw_transcript += f"\n{body}"

    return CapturedResponse(
        url=url,
        method=method,
        status=status_code,
        headers=headers_list,
        body=body,
        elapsed_ms=elapsed_ms,
        raw_text=raw_transcript,
        truncated=truncated,
    )
