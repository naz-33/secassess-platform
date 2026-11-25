import re
import shlex
import subprocess
import time
import urllib.parse
import uuid
from typing import Optional, Tuple, List, Dict
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.exceptions import ScopeViolationException
from app.modules.audit import AuditService
from app.modules.scans import save_raw_artifact, to_raw_bytes
from app.modules.targets import ScopeManager
from app.modules.web_assessment.parsers.curl_parser import (
    DEFAULT_USER_AGENT,
    parse_raw_curl_response,
)
from app.modules.web_assessment.types import CapturedResponse

ALLOWED_HTTP_METHODS = {"GET", "HEAD", "OPTIONS"}
CURL_PARTIAL_FILE_EXIT_CODE = 18


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
        per_request_timeout: Optional[int] = None,
        max_body_bytes: Optional[int] = None,
        scan_id: Optional[uuid.UUID] = None,
    ):
        self.db = db
        self.target_id = target_id
        self.user_id = user_id
        self.scan_id = scan_id
        self.scope_manager = ScopeManager(db)
        self.audit_service = AuditService(db)

        raw_delay = delay_ms if delay_ms is not None else settings.WEB_RATE_LIMIT_DELAY_MS
        raw_max_requests = max_requests if max_requests is not None else settings.WEB_MAX_REQUESTS_CAP
        raw_timeout = per_request_timeout if per_request_timeout is not None else settings.WEB_REQUEST_TIMEOUT_SECONDS
        raw_max_body = max_body_bytes if max_body_bytes is not None else settings.WEB_MAX_BODY_SIZE_BYTES

        self.delay_ms = max(int(raw_delay), settings.WEB_RATE_LIMIT_DELAY_MS)
        self.max_requests = max(1, min(int(raw_max_requests), settings.WEB_MAX_REQUESTS_CAP))
        self.per_request_timeout = max(1, min(int(raw_timeout), settings.WEB_REQUEST_TIMEOUT_SECONDS))
        self.max_body_bytes = max(1, min(int(raw_max_body), settings.WEB_MAX_BODY_SIZE_BYTES))
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

            # 2b. Resolve DNS once and authorize all resolved IPs before pinning
            parsed_current = urllib.parse.urlsplit(current_url)
            target_host = parsed_current.hostname or ""
            target_port = parsed_current.port or (
                443 if parsed_current.scheme.lower() == "https" else 80
            )
            try:
                resolved_ips = self.scope_manager.resolve_and_authorize(
                    self.target_id,
                    target_host,
                    target_port,
                )
            except ScopeViolationException as exc:
                rejection_msg = f"[SCOPE REJECTED] DNS resolution blocked for '{current_url}': {exc.detail}"
                overall_transcript += f"{rejection_msg}\n"
                self.audit_service.log_action(
                    action="web_probe_rejected",
                    detail={
                        "target_id": str(self.target_id),
                        "url": current_url,
                        "host": target_host,
                        "port": target_port,
                        "reason": str(exc.detail),
                    },
                    user_id=self.user_id,
                )
                return last_response, overall_transcript

            pinned_ip = resolved_ips[0]
            formatted_ip = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
            resolve_entry = f"{target_host}:{target_port}:{formatted_ip}"
            self.audit_service.log_action(
                action="web_probe_resolved",
                detail={
                    "target_id": str(self.target_id),
                    "url": current_url,
                    "host": target_host,
                    "port": target_port,
                    "resolved_ips": resolved_ips,
                    "pinned_ip": pinned_ip,
                },
                user_id=self.user_id,
            )

            # 3. Rate limit delay
            if self.requests_count > 0 and self.delay_ms > 0:
                time.sleep(self.delay_ms / 1000.0)

            # 4. Prepare command arguments (Strict allow-list, shell=False, never -L)
            per_req_timeout = self.per_request_timeout
            max_size = self.max_body_bytes

            cmd: List[str] = [
                settings.CURL_PATH,
                "-sS",
                "-i",
                "--max-time",
                str(per_req_timeout),
                "--max-filesize",
                str(max_size),
                "--resolve",
                resolve_entry,
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
                    text=False,
                    timeout=per_req_timeout + 5,
                )
                raw_stdout_bytes = to_raw_bytes(proc.stdout)
                raw_stderr_bytes = to_raw_bytes(proc.stderr)
                decoded_stdout = raw_stdout_bytes.decode("utf-8", errors="replace")
                decoded_stderr = raw_stderr_bytes.decode("utf-8", errors="replace")

                has_http_response = bool(
                    re.search(r"^HTTP/\S+\s+\d{3}", decoded_stdout, re.MULTILINE)
                )
                partial_transfer = (
                    proc.returncode == CURL_PARTIAL_FILE_EXIT_CODE and has_http_response
                )
                if proc.returncode != 0 and not partial_transfer:
                    error_detail = (decoded_stderr or decoded_stdout).strip()
                    err_msg = (
                        f"[CURL ERROR] Curl exited with status {proc.returncode} "
                        f"for '{current_url}'."
                    )
                    if error_detail:
                        err_msg += f" {error_detail}"
                    overall_transcript += f"{err_msg}\n"
                    return None, overall_transcript
                raw_out = decoded_stdout
                if decoded_stderr:
                    overall_transcript += f"[CURL STDERR] {decoded_stderr.strip()}\n"
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
            if self.scan_id is not None:
                artifact = save_raw_artifact(
                    self.db,
                    scan_id=self.scan_id,
                    tool="curl",
                    stdout_bytes=raw_stdout_bytes,
                    stderr_bytes=raw_stderr_bytes,
                    command=" ".join(shlex.quote(arg) for arg in cmd),
                    target_url=current_url,
                    exit_code=proc.returncode,
                    duration_ms=t_elapsed,
                )
                captured.artifact_file_path = artifact.file_path
                captured.artifact_sha256 = artifact.sha256
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
