"""Generic, safe, tool-agnostic scan runner enforcing scope and security constraints."""
import shlex
import subprocess
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, Type

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import NotFoundException, ScopeViolationException
from app.modules.audit import AuditService
from app.modules.targets import TargetService
from app.modules.recon import ReconService
from app.modules.assessments.service import AssessmentService
from app.modules.scans.models import Scan, ScanStatus, ScanTool
from app.modules.scans.repository import ScanRepository
from app.modules.scans.validator import validate_scan_target
from app.modules.scans.adapters import ToolAdapter, NmapAdapter, DnsAdapter


class ScanRunner:
    """Tool-agnostic execution runner enforcing scope validation and process safety."""

    ADAPTERS: Dict[str, Type[ToolAdapter]] = {
        ScanTool.NMAP.value: NmapAdapter,
        ScanTool.DNS.value: DnsAdapter,
    }

    def __init__(self, db: Session):
        self.db = db
        self.repository = ScanRepository(db)
        self.target_service = TargetService(db)
        self.audit_service = AuditService(db)
        self.recon_service = ReconService(db)
        self.assessment_service = AssessmentService(db)

    def get_adapter(self, tool_name: str) -> ToolAdapter:
        """Resolve adapter for the requested tool."""
        key = tool_name.lower().strip()
        adapter_cls = self.ADAPTERS.get(key)
        if not adapter_cls:
            raise ValueError(
                f"Unsupported scanner tool: '{tool_name}'. Allowed tools: {sorted(self.ADAPTERS.keys())}"
            )
        return adapter_cls()

    def validate_and_prepare(
        self,
        assessment_id: uuid.UUID,
        tool: str,
        target: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
        user_id: Optional[uuid.UUID] = None,
    ) -> Tuple[Scan, ToolAdapter, list[str] | list[list[str]]]:
        """
        Validate assessment, tool, target, and scope before any execution.
        If scope fails, creates a rejected scan record, writes an audit log, and raises ScopeViolationException.

        Returns:
            (created_scan, adapter_instance, argv_list)
        """
        # 1. Verify assessment exists
        assessment = self.assessment_service.get_assessment(assessment_id)
        if not assessment:
            raise NotFoundException("Assessment", assessment_id)

        # 2. Resolve adapter
        adapter = self.get_adapter(tool)

        # 3. Resolve target (defaults to target base_url if not specified)
        target_to_scan = target
        if not target_to_scan or not str(target_to_scan).strip():
            target_obj = self.target_service.get_target(assessment.target_id)
            if not target_obj:
                raise NotFoundException("Target", assessment.target_id)
            target_to_scan = target_obj.base_url

        # 4. Input validation (rejects metacharacters, whitespace, leading '-')
        # validate_scan_target raises ValueError on violation
        valid_host = validate_scan_target(target_to_scan)

        # 5. Build command argv list (enforces option allow-listing)
        if isinstance(adapter, DnsAdapter):
            argv = adapter.build_commands(valid_host, options or {})
            command_str = "\n".join(
                " ".join(shlex.quote(arg) for arg in command)
                for command in argv
            )
        else:
            argv = adapter.build_command(valid_host, options or {})
            command_str = " ".join(shlex.quote(arg) for arg in argv)

        # 6. Validate scope using TargetService (MANDATORY SCOPE CHECK)
        in_scope, reason = self.target_service.scope_manager.check_scope(
            assessment.target_id, target_to_scan
        )
        if not in_scope:
            # Create rejected scan row
            scan = Scan(
                assessment_id=assessment_id,
                tool=ScanTool(adapter.tool_name),
                command=command_str,
                status=ScanStatus.REJECTED,
                error=f"Scope violation: {reason}",
                finished_at=datetime.now(timezone.utc),
            )
            created_rejected = self.repository.create(scan)

            # Record audit trail
            self.audit_service.log_action(
                action="scan_rejected",
                detail={
                    "assessment_id": str(assessment_id),
                    "scan_id": str(created_rejected.id),
                    "tool": adapter.tool_name,
                    "target": target_to_scan,
                    "reason": reason,
                },
                user_id=user_id,
            )

            # Raise 403 exception without starting any subprocess
            raise ScopeViolationException(asset=target_to_scan, target_id=assessment.target_id)

        # 7. Concurrency checks
        running_scans = self.repository.list_running_by_assessment(assessment_id)
        if running_scans:
            raise ValueError(
                f"Another scan is currently in progress for assessment '{assessment_id}'"
            )

        active_global = self.repository.count_active_scans()
        if active_global >= settings.MAX_CONCURRENT_SCANS:
            raise ValueError(
                f"Global concurrency limit reached ({settings.MAX_CONCURRENT_SCANS} concurrent scans active)"
            )

        # 8. Create pending scan row
        scan = Scan(
            assessment_id=assessment_id,
            tool=ScanTool(adapter.tool_name),
            command=command_str,
            status=ScanStatus.PENDING,
        )
        created_scan = self.repository.create(scan)

        # Audit entry: scan enqueued/started
        self.audit_service.log_action(
            action="scan_started",
            detail={
                "assessment_id": str(assessment_id),
                "scan_id": str(created_scan.id),
                "tool": adapter.tool_name,
                "target": target_to_scan,
                "command": command_str,
            },
            user_id=user_id,
        )

        return created_scan, adapter, argv

    def execute_scan(
        self,
        scan_id: uuid.UUID,
        argv: Optional[list[str] | list[list[str]]] = None,
        user_id: Optional[uuid.UUID] = None,
    ) -> Scan:
        """
        Execute the tool subprocess for an enqueued scan, parse output, and record assets.
        """
        scan = self.repository.get_by_id(scan_id)
        if not scan:
            raise NotFoundException("Scan", scan_id)

        adapter = self.get_adapter(scan.tool.value)
        if scan.tool == ScanTool.DNS:
            if argv and isinstance(argv[0], list):
                command_plan = argv
            elif argv:
                command_plan = [argv]
            elif scan.command:
                command_plan = [
                    shlex.split(line)
                    for line in scan.command.splitlines()
                    if line.strip()
                ]
            else:
                command_plan = adapter.build_commands("localhost")
        else:
            command_argv = argv if argv and isinstance(argv[0], str) else []
            if not command_argv:
                command_argv = adapter.build_command("localhost")
            command_plan = [command_argv]

        # Update status to running
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        self.repository.update(scan)

        timeout = settings.SCAN_TIMEOUT_SECONDS
        raw_output = ""
        parse_output = ""
        output_parts: list[str] = []
        execution_errors: list[str] = []

        try:
            if scan.tool == ScanTool.DNS:
                any_answer = False
                for command in command_plan:
                    record_type = adapter.command_record_type(command)
                    output_parts.append(
                        f"$ {' '.join(shlex.quote(arg) for arg in command)}\n"
                    )
                    proc = subprocess.run(
                        command,
                        shell=False,
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                    )
                    if proc.returncode != 0:
                        execution_errors.append(
                            f"{record_type} query exited with status {proc.returncode}"
                        )
                    if proc.stdout:
                        output_parts.append(proc.stdout)
                        any_answer = any_answer or bool(proc.stdout.strip())
                        if not proc.stdout.endswith("\n"):
                            output_parts.append("\n")
                    if proc.stderr:
                        output_parts.append("[STDERR]\n")
                        output_parts.append(proc.stderr)
                        if not proc.stderr.endswith("\n"):
                            output_parts.append("\n")
                    if not proc.stdout.strip():
                        output_parts.append(f"No {record_type} records returned\n")
                    raw_output = "".join(output_parts)
                parse_output = raw_output
                if not any_answer:
                    if not execution_errors:
                        output_parts.append("No DNS data returned for any query.\n")
                        scan.error = "DNS queries completed with no records returned."
                raw_output = "".join(output_parts)
            else:
                # Strict safe execution: shell=False, argv list, timeout enforced
                proc = subprocess.run(
                    command_plan[0],
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                raw_output = proc.stdout
                parse_output = proc.stdout
                if proc.returncode != 0:
                    execution_errors.append(f"Scanner exited with status {proc.returncode}")
                if proc.stderr and not raw_output:
                    raw_output = proc.stderr
                elif proc.stderr:
                    raw_output = f"{proc.stdout}\n[STDERR]\n{proc.stderr}"

            scan.raw_output = raw_output

            # Parse discovered assets
            try:
                parsed_assets = adapter.parse(parse_output)
            except Exception as parse_err:
                scan.status = ScanStatus.FAILED
                scan.error = f"Output parsing error: {parse_err}"
                scan.finished_at = datetime.now(timezone.utc)
                self.repository.update(scan)
                self.audit_service.log_action(
                    action="scan_failed",
                    detail={"scan_id": str(scan.id), "error": scan.error},
                    user_id=user_id,
                )
                return scan

            # Store discovered assets in database
            self.recon_service.create_assets_from_scan(
                assessment_id=scan.assessment_id,
                scan_id=scan.id,
                parsed_items=parsed_assets,
            )

            if execution_errors:
                scan.status = ScanStatus.FAILED
                scan.error = "; ".join(execution_errors)
                scan.finished_at = datetime.now(timezone.utc)
                self.repository.update(scan)
                self.audit_service.log_action(
                    action="scan_failed",
                    detail={
                        "scan_id": str(scan.id),
                        "error": scan.error,
                        "partial_assets_count": len(parsed_assets),
                    },
                    user_id=user_id,
                )
                return scan

            scan.status = ScanStatus.COMPLETED
            scan.finished_at = datetime.now(timezone.utc)
            self.repository.update(scan)

            self.audit_service.log_action(
                action="scan_completed",
                detail={
                    "scan_id": str(scan.id),
                    "tool": scan.tool.value,
                    "assets_count": len(parsed_assets),
                },
                user_id=user_id,
            )
            return scan

        except FileNotFoundError:
            scan.status = ScanStatus.FAILED
            executable = command_plan[0][0] if command_plan else "unknown"
            scan.error = f"Tool executable '{executable}' not found on system PATH. Please configure path in settings."
            scan.finished_at = datetime.now(timezone.utc)
            self.repository.update(scan)
            self.audit_service.log_action(
                action="scan_failed",
                detail={"scan_id": str(scan.id), "error": scan.error},
                user_id=user_id,
            )
            return scan

        except subprocess.TimeoutExpired as te:
            scan.status = ScanStatus.FAILED
            raw_partial = te.output if getattr(te, "output", None) else (getattr(te, "stdout", None) or "")
            timeout_output = raw_output or "".join(output_parts)
            if raw_partial:
                timeout_output += (
                    raw_partial.decode("utf-8", errors="replace")
                    if isinstance(raw_partial, bytes)
                    else str(raw_partial)
                )
            scan.raw_output = timeout_output
            scan.error = f"Scan execution timed out after {timeout} seconds"
            scan.finished_at = datetime.now(timezone.utc)
            self.repository.update(scan)
            self.audit_service.log_action(
                action="scan_failed",
                detail={"scan_id": str(scan.id), "error": scan.error},
                user_id=user_id,
            )
            return scan

        except Exception as exc:
            scan.status = ScanStatus.FAILED
            scan.raw_output = raw_output
            scan.error = f"Unexpected scan failure: {exc}"
            scan.finished_at = datetime.now(timezone.utc)
            self.repository.update(scan)
            self.audit_service.log_action(
                action="scan_failed",
                detail={"scan_id": str(scan.id), "error": scan.error},
                user_id=user_id,
            )
            return scan

    def run(
        self,
        assessment_id: uuid.UUID,
        tool: str,
        target: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
        user_id: Optional[uuid.UUID] = None,
    ) -> Scan:
        """Synchronously validate, prepare, and execute a tool scan end-to-end."""
        scan, _, argv = self.validate_and_prepare(
            assessment_id=assessment_id,
            tool=tool,
            target=target,
            options=options,
            user_id=user_id,
        )
        return self.execute_scan(scan_id=scan.id, argv=argv, user_id=user_id)
