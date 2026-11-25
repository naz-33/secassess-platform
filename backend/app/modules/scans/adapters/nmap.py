"""Nmap tool adapter enforcing strict safe profile and allow-listed parameters."""
import re
from typing import List, Dict, Any
from app.core.config import settings
from app.modules.scans.adapters.base import ToolAdapter
from app.modules.scans.validator import validate_scan_target
from app.modules.recon import NmapParser

SAFE_PORT_RANGE_REGEX = re.compile(r"^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$")


def _validate_custom_ports(ports_val: str, max_ports: int) -> None:
    """Validate custom Nmap port ranges are within 1-65535 and total unique ports <= max_ports."""
    if not SAFE_PORT_RANGE_REGEX.match(ports_val):
        raise ValueError(f"Invalid port specification '{ports_val}'. Must match '80,443' or '1-1024'.")

    items = ports_val.split(",")
    if len(items) > max_ports:
        raise ValueError(
            f"Too many port specification items ({len(items)}). Maximum allowed is {max_ports}."
        )

    intervals: List[tuple[int, int]] = []
    for item in items:
        if "-" in item:
            start_str, end_str = item.split("-", 1)
            start, end = int(start_str), int(end_str)
        else:
            start = end = int(item)

        if not (1 <= start <= end <= 65535):
            raise ValueError(
                f"Invalid port range '{item}'. Ports must satisfy 1 <= start <= end <= 65535."
            )
        if (end - start + 1) > max_ports:
            raise ValueError(
                f"Port range '{item}' exceeds maximum allowed port count of {max_ports}."
            )
        intervals.append((start, end))

    intervals.sort()
    merged: List[List[int]] = []
    for start, end in intervals:
        if merged and start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])

    unique_count = sum(end - start + 1 for start, end in merged)
    if unique_count > max_ports:
        raise ValueError(
            f"Custom ports specify {unique_count} unique ports, exceeding maximum allowed ({max_ports})."
        )


class NmapAdapter(ToolAdapter):
    """Adapter executing Nmap port and service version scans within strict safe limits."""

    def __init__(self, parser: NmapParser | None = None):
        self._parser = parser or NmapParser()

    @property
    def tool_name(self) -> str:
        return "nmap"

    def build_command(self, target: str, options: Dict[str, Any] | None = None) -> List[str]:
        """
        Build argv list for Nmap ensuring safe flags and no arbitrary pass-through.

        Allowed options:
            - top_ports (int, 1-1000, default 100)
            - ports (str, e.g. "80,443" or "1-1024", safe regex)
            - timing (str, "-T0" to "-T4", default "-T3")
            - service_version (bool, default True -> "-sV")
        """
        valid_host = validate_scan_target(target)
        opts = options or {}

        # Disallow raw flags or unknown keys
        allowed_keys = {"top_ports", "ports", "timing", "service_version"}
        unknown_keys = set(opts.keys()) - allowed_keys
        if unknown_keys:
            raise ValueError(f"Disallowed Nmap scan options: {sorted(unknown_keys)}")

        argv = [settings.NMAP_PATH]

        # Service version detection
        service_version = opts.get("service_version", True)
        if service_version:
            argv.append("-sV")

        # Force XML output to stdout for safe parsing
        argv.extend(["-oX", "-"])

        # Timing template (-T0 to -T4 allowed; -T5 strictly forbidden)
        timing = opts.get("timing", "-T3")
        if timing not in {"-T0", "-T1", "-T2", "-T3", "-T4"}:
            raise ValueError(f"Invalid or disallowed timing option '{timing}'. Only -T0 through -T4 are permitted.")
        argv.append(timing)

        # Port specifications
        if "ports" in opts and opts["ports"] is not None and str(opts["ports"]).strip():
            ports_val = str(opts["ports"]).strip()
            _validate_custom_ports(ports_val, settings.NMAP_MAX_CUSTOM_PORTS)
            argv.extend(["-p", ports_val])
        else:
            top_ports = opts.get("top_ports", 100)
            if isinstance(top_ports, bool):
                raise ValueError(f"top_ports must be an integer between 1 and 1000, got: {top_ports}")
            try:
                top_ports_int = int(top_ports)
                if not (1 <= top_ports_int <= 1000):
                    raise ValueError
            except (ValueError, TypeError):
                raise ValueError(f"top_ports must be an integer between 1 and 1000, got: {top_ports}")
            argv.extend(["--top-ports", str(top_ports_int)])

        # Target always placed as final argument
        argv.append(valid_host)
        return argv

    def parse(self, raw_output: str) -> List[Dict[str, Any]]:
        return self._parser.parse(raw_output)
