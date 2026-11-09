"""Input validation and sanitization for scanner targets and parameters."""
import ipaddress
import re
from urllib.parse import urlsplit


FORBIDDEN_METACHARS_REGEX = re.compile(r"[\s;&|`$<>()\\!\"'\r\n\t]")
HOSTNAME_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)


def validate_scan_target(target: str) -> str:
    """
    Validates scan target string for safe subprocess execution.

    Requirements:
    - Rejects anything starting with '-' (flag injection prevention).
    - Rejects shell metacharacters and whitespace.
    - Resolves to a valid hostname, IP address, or URL host.

    Returns:
        The extracted hostname or IP string suitable for scanner argv.

    Raises:
        ValueError: If validation fails.
    """
    if not target or not isinstance(target, str):
        raise ValueError("Target must be a non-empty string")

    raw = target.strip()
    if not raw:
        raise ValueError("Target cannot be empty or whitespace only")

    # Reject leading '-' (prevents CLI argument injection)
    if raw.startswith("-"):
        raise ValueError(f"Scan target '{raw}' cannot start with '-' (flag injection rejected)")

    # Reject shell metacharacters and internal whitespace
    if FORBIDDEN_METACHARS_REGEX.search(raw):
        raise ValueError(
            f"Scan target '{raw}' contains forbidden shell metacharacters or whitespace"
        )

    # If it's a URL (http:// or https://), extract hostname
    extracted_host = raw
    if raw.startswith(("http://", "https://")):
        try:
            parsed = urlsplit(raw)
            if not parsed.hostname:
                raise ValueError(f"Could not extract hostname from URL '{raw}'")
            extracted_host = parsed.hostname
        except Exception as e:
            raise ValueError(f"Malformed URL target '{raw}': {e}")
    elif ":" in raw and not raw.startswith("["):
        # Could be host:port (e.g. localhost:3000, 192.168.1.1:8080) or IPv6
        # Check if it's a valid IPv6 address first
        try:
            ipaddress.ip_address(raw)
            extracted_host = raw
        except ValueError:
            # Check host:port
            parts = raw.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                extracted_host = parts[0]
            else:
                pass

    # Verify extracted_host is valid IP or RFC-compliant hostname
    # Check IP
    try:
        ipaddress.ip_address(extracted_host)
        return extracted_host
    except ValueError:
        pass

    # Check hostname
    if HOSTNAME_REGEX.match(extracted_host):
        return extracted_host

    raise ValueError(
        f"Target '{raw}' does not resolve to a valid hostname or IP address"
    )

