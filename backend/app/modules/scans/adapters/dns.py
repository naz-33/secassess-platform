"""DNS tool adapter using dig with fallback to nslookup and safe record filtering."""
import ipaddress
import shutil
from typing import List, Dict, Any
from app.core.config import settings
from app.modules.scans.adapters.base import ToolAdapter
from app.modules.scans.validator import validate_scan_target
from app.modules.recon import DnsParser

ALLOWED_DNS_RECORDS = {"A", "AAAA", "MX", "NS", "TXT", "CNAME"}


def is_ip_or_localhost(host: str) -> bool:
    """Check if host string is a numeric IP or localhost."""
    clean = host.lower().strip()
    if clean in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False


class DnsAdapter(ToolAdapter):
    """Adapter for DNS reconnaissance queries using dig with nslookup fallback."""

    def __init__(self, parser: DnsParser | None = None):
        self._parser = parser or DnsParser()

    @property
    def tool_name(self) -> str:
        return "dns"

    def resolve_executable(self) -> str:
        """Find dig or nslookup on system PATH or configured settings."""
        # Check dig first
        dig_bin = settings.DIG_PATH
        if shutil.which(dig_bin):
            return dig_bin
        if shutil.which("dig"):
            return "dig"

        # Fallback to nslookup
        nslookup_bin = settings.NSLOOKUP_PATH
        if shutil.which(nslookup_bin):
            return nslookup_bin
        if shutil.which("nslookup"):
            return "nslookup"

        # Default to configured dig path (runner will report missing executable gracefully)
        return dig_bin

    def build_commands(self, target: str, options: Dict[str, Any] | None = None) -> List[List[str]]:
        """Build one safe argv command per requested DNS record type."""
        valid_host = validate_scan_target(target)
        opts = options or {}

        # Validate options
        allowed_keys = {"record_types", "record_type"}
        unknown_keys = set(opts.keys()) - allowed_keys
        if unknown_keys:
            raise ValueError(f"Disallowed DNS scan options: {sorted(unknown_keys)}")

        # Check record types
        selected_records: List[str] = []
        if "record_types" in opts and opts["record_types"]:
            req_types = opts["record_types"]
            if isinstance(req_types, str):
                req_types = [req_types]
            for r in req_types:
                r_upper = str(r).upper().strip()
                if r_upper not in ALLOWED_DNS_RECORDS:
                    raise ValueError(f"Disallowed DNS record type '{r}'. Allowed: {sorted(ALLOWED_DNS_RECORDS)}")
                selected_records.append(r_upper)
        elif "record_type" in opts and opts["record_type"]:
            r_upper = str(opts["record_type"]).upper().strip()
            if r_upper not in ALLOWED_DNS_RECORDS:
                raise ValueError(f"Disallowed DNS record type '{r_upper}'. Allowed: {sorted(ALLOWED_DNS_RECORDS)}")
            selected_records.append(r_upper)
        executable = self.resolve_executable()
        try:
            ipaddress.ip_address(valid_host)
            is_ip_target = True
        except ValueError:
            is_ip_target = False

        if is_ip_target:
            if "dig" in executable.lower():
                return [[executable, "-x", valid_host, "+noall", "+answer"]]
            return [[executable, "-type=PTR", valid_host]]

        if not selected_records:
            selected_records = ["A", "AAAA", "NS", "MX", "TXT"]
        selected_records = list(dict.fromkeys(selected_records))

        if "dig" in executable.lower():
            return [
                [executable, valid_host, record_type, "+noall", "+answer"]
                for record_type in selected_records
            ]
        return [
            [executable, f"-type={record_type}", valid_host]
            for record_type in selected_records
        ]

    def build_command(self, target: str, options: Dict[str, Any] | None = None) -> List[str]:
        """Build the primary argv command for compatibility with single-command callers."""
        return self.build_commands(target, options)[0]

    @staticmethod
    def command_record_type(command: List[str]) -> str:
        """Return the record type represented by a DNS argv command."""
        if "-x" in command:
            return "PTR"
        for arg in command:
            if arg.startswith("-type="):
                return arg.split("=", 1)[1].upper()
            if arg.upper() in ALLOWED_DNS_RECORDS:
                return arg.upper()
        return "DNS"

    def parse(self, raw_output: str) -> List[Dict[str, Any]]:
        return self._parser.parse(raw_output)
