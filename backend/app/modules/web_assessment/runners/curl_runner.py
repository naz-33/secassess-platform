import re
import subprocess
import time
import urllib.parse
import uuid
from typing import Optional, Tuple, List, Dict
from sqlalchemy.orm import Session
from app.core.config import settings
from app.modules.audit import AuditService
from app.modules.targets import ScopeManager
from app.modules.web_assessment.types import CapturedResponse

ALLOWED_HTTP_METHODS = {"GET", "HEAD", "OPTIONS"}
DEFAULT_USER_AGENT = "SecAssess/1.0 Web Security Scanner"
CURL_PARTIAL_FILE_EXIT_CODE = 18


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

    # Assemble raw transcript
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


class CurlRunner:
    """
    Subprocess-based HTTP probing runner enforcing:
    1. Scope validation before every request and every redirect hop.
    2. Subprocess execution with shell=False and strict allow-listed flags.
    3. Manual redirect following up to 3 hops (never automatic).
    4. Rate limit delay and hard max requests cap.
    """

    def __init__(
        self,
        db: Session,
        target_id: uuid.UUID,
        user_id: Optional[uuid.UUID] = None,
        delay_ms: Optional[int] = None,
        max_requests: Optional[int] = None,
    ):
        self.db = db
        self.target_id = target_id
        self.user_id = user_id
        self.scope_manager = ScopeManager(db)
        self.audit_service = AuditService(db)
        self.delay_ms = delay_ms if delay_ms is not None else settings.WEB_RATE_LIMIT_DELAY_MS
        self.max_requests = max_requests if max_requests is not None else settings.WEB_MAX_REQUESTS_CAP
        self.requests_count = 0

    def probe(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        follow_redirects: bool = True,
        max_hops: int = 3,
    ) -> Tuple[Optional[CapturedResponse], str]:
        """
        Execute an HTTP probe against the target URL.
        Returns:
            (CapturedResponse, transcript_log)
            CapturedResponse is None if the probe was rejected by scope or hit request cap.
        """
        current_method = method.upper().strip()
        if current_method not in ALLOWED_HTTP_METHODS:
            raise ValueError(f"HTTP method '{current_method}' not permitted. Allowed methods: {ALLOWED_HTTP_METHODS}")

        current_url = url
        current_hops = 0
        overall_transcript = ""
        last_response: Optional[CapturedResponse] = None

        while current_hops <= max_hops:
            # 1. Cap check
            if self.requests_count >= self.max_requests:
                msg = f"[REQUEST CAP REACHED] Limit of {self.max_requests} requests reached. Skipping '{current_url}'."
                overall_transcript += f"{msg}\n"
                return last_response, overall_transcript

            # 2. Scope validation (MANDATORY SCOPE CHECK)
            in_scope, reason = self.scope_manager.check_scope(self.target_id, current_url)
            if not in_scope:
                rejection_msg = f"[SCOPE REJECTED] URL '{current_url}' is out of scope: {reason}"
                overall_transcript += f"{rejection_msg}\n"
                # Audit log rejection
                self.audit_service.log_action(
                    action="web_probe_rejected",
                    detail={
                        "target_id": str(self.target_id),
                        "url": current_url,
                        "reason": reason,
                    },
                    user_id=self.user_id,
                )
                return last_response, overall_transcript

            # 3. Rate limit delay
            if self.requests_count > 0 and self.delay_ms > 0:
                time.sleep(self.delay_ms / 1000.0)

            # 4. Prepare command arguments (Strict allow-list, shell=False)
            per_req_timeout = settings.WEB_REQUEST_TIMEOUT_SECONDS
            max_size = settings.WEB_MAX_BODY_SIZE_BYTES

            cmd: List[str] = [
                settings.CURL_PATH,
                "-sS",
                "-i",
                "--max-time",
                str(per_req_timeout),
                "--max-filesize",
                str(max_size),
                "-A",
                DEFAULT_USER_AGENT,
                "-X",
                current_method,
            ]

            if headers:
                for hk, hv in headers.items():
                    cmd.extend(["-H", f"{hk}: {hv}"])

            cmd.append(current_url)

            # 5. Execute probe
            t_start = time.perf_counter()
            self.requests_count += 1

            try:
                proc = subprocess.run(
                    cmd,
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=per_req_timeout + 5,
                )
                has_http_response = bool(
                    re.search(r"^HTTP/\S+\s+\d{3}", proc.stdout or "", re.MULTILINE)
                )
                partial_transfer = (
                    proc.returncode == CURL_PARTIAL_FILE_EXIT_CODE and has_http_response
                )
                if proc.returncode != 0 and not partial_transfer:
                    error_detail = (proc.stderr or proc.stdout or "").strip()
                    err_msg = (
                        f"[CURL ERROR] Curl exited with status {proc.returncode} "
                        f"for '{current_url}'."
                    )
                    if error_detail:
                        err_msg += f" {error_detail}"
                    overall_transcript += f"{err_msg}\n"
                    return None, overall_transcript
                raw_out = proc.stdout or ""
                if proc.stderr:
                    overall_transcript += f"[CURL STDERR] {proc.stderr.strip()}\n"
                if partial_transfer:
                    overall_transcript += (
                        "[CURL PARTIAL RESPONSE] Transfer ended before the declared "
                        "Content-Length; findings are based on the received bytes.\n"
                    )
            except FileNotFoundError:
                err_msg = f"[EXEC ERROR] Curl binary '{settings.CURL_PATH}' not found on system PATH."
                overall_transcript += f"{err_msg}\n"
                return None, overall_transcript
            except subprocess.TimeoutExpired:
                err_msg = f"[TIMEOUT] Probe to '{current_url}' timed out after {per_req_timeout}s."
                overall_transcript += f"{err_msg}\n"
                return None, overall_transcript
            except Exception as exc:
                err_msg = f"[ERROR] Unexpected probe error on '{current_url}': {exc}"
                overall_transcript += f"{err_msg}\n"
                return None, overall_transcript

            t_elapsed = (time.perf_counter() - t_start) * 1000.0
            captured = parse_raw_curl_response(
                raw_output=raw_out,
                url=current_url,
                method=current_method,
                elapsed_ms=t_elapsed,
                max_body_bytes=max_size,
                response_truncated=partial_transfer,
            )
            last_response = captured
            overall_transcript += f"\n--- Probe Transcript for {current_url} ---\n{captured.raw_text}\n"

            # 6. Manual redirect handling
            if follow_redirects and captured.status in (301, 302, 303, 307, 308) and current_hops < max_hops:
                location = captured.get_header("Location")
                if location:
                    next_url = urllib.parse.urljoin(current_url, location)
                    current_url = next_url
                    current_hops += 1
                    current_method = "GET"  # Standard redirect behavior converts to GET
                    continue

            break

        return last_response, overall_transcript
