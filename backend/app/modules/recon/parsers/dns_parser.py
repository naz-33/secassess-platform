"""DNS lookup output parser for extracting discovered records."""
import re
from typing import List, Dict, Any


# Standard dig line format: <name> <ttl> <class> <type> <value>
# e.g.: example.com. 300 IN A 93.184.216.34
DIG_ANSWER_REGEX = re.compile(
    r"^(\S+)\s+(\d+)\s+IN\s+([A-Z]+)\s+(.+)$",
    re.IGNORECASE,
)

# nslookup standard response lines:
# Name:    example.com
# Address: 93.184.216.34
NSLOOKUP_ADDR_REGEX = re.compile(r"^(?:Address|Addresses):\s+(.+)$", re.IGNORECASE)


class DnsParser:
    """Parses DNS tool output (dig or nslookup) into structured asset dicts."""

    def parse(self, raw_output: str) -> List[Dict[str, Any]]:
        """
        Parse raw DNS lookup output into a list of structured asset dicts.

        Args:
            raw_output: Text output produced by dig or nslookup.

        Returns:
            List of dictionaries with keys: 'type', 'value', 'details'.
        """
        if not raw_output or not raw_output.strip():
            return []

        # Handle explicit localhost/IP notice
        if "no dns records for this target type" in raw_output.lower():
            return []

        assets: List[Dict[str, Any]] = []

        lines = raw_output.strip().splitlines()
        for line in lines:
            line_str = line.strip()
            if not line_str or line_str.startswith(";"):
                continue

            # Try parsing dig format
            match = DIG_ANSWER_REGEX.match(line_str)
            if match:
                rec_name = match.group(1).rstrip(".")
                ttl = int(match.group(2))
                rec_type = match.group(3).upper()
                rec_val = match.group(4).strip().strip('"')

                # Filter allowed record types
                if rec_type in {"A", "AAAA", "CNAME"}:
                    assets.append({
                        "type": "host",
                        "value": rec_val,
                        "details": {
                            "name": rec_name,
                            "record_type": rec_type,
                            "value": rec_val,
                            "ttl": ttl,
                        },
                    })
                elif rec_type in {"MX", "NS", "TXT"}:
                    assets.append({
                        "type": "service",
                        "value": f"{rec_type}:{rec_name}",
                        "details": {
                            "name": rec_name,
                            "record_type": rec_type,
                            "value": rec_val,
                            "ttl": ttl,
                        },
                    })
                continue

            # Fallback nslookup answer parsing
            ns_match = NSLOOKUP_ADDR_REGEX.match(line_str)
            if ns_match:
                ip_val = ns_match.group(1).strip()
                # Ignore loopback or typical local DNS servers
                if ip_val and not ip_val.startswith("#"):
                    assets.append({
                        "type": "host",
                        "value": ip_val,
                        "details": {
                            "record_type": "A",
                            "value": ip_val,
                            "source": "nslookup",
                        },
                    })

        unique_assets: List[Dict[str, Any]] = []
        seen = set()
        for asset in assets:
            key = (asset["type"], asset["value"])
            if key not in seen:
                seen.add(key)
                unique_assets.append(asset)
        return unique_assets
