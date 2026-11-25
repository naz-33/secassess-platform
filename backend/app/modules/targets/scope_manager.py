import ipaddress
import re
import socket
import uuid
from typing import List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundException, ScopeViolationException
from app.modules.targets.models import Target, ScopeItem


LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _parse_asset(asset: str) -> dict:
    """
    Parse an asset string (URL, host:port, IP/CIDR, or domain) into components.
    """
    asset = asset.strip()
    if not asset:
        return {"raw": asset, "valid": False}

    # Check for CIDR block (e.g. 192.168.1.0/24)
    if "/" in asset and not asset.startswith(("http://", "https://")):
        try:
            net = ipaddress.ip_network(asset, strict=False)
            return {
                "raw": asset,
                "valid": True,
                "is_network": True,
                "network": net,
                "host": None,
                "port": None,
                "path": None,
            }
        except ValueError:
            pass

    # Prepend scheme if missing but looks like host:port or URL path
    has_scheme = asset.startswith(("http://", "https://"))
    url_to_parse = asset if has_scheme else f"http://{asset}"

    try:
        parsed = urlsplit(url_to_parse)
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
        path = parsed.path or ""

        # Check if hostname is an IP
        ip_obj = None
        if hostname:
            try:
                ip_obj = ipaddress.ip_address(hostname)
            except ValueError:
                ip_obj = None

        return {
            "raw": asset,
            "valid": bool(hostname or path),
            "scheme": parsed.scheme if has_scheme else None,
            "hostname": hostname,
            "port": port,
            "path": path,
            "ip": ip_obj,
            "is_network": False,
        }
    except Exception:
        return {"raw": asset, "valid": False}


def _matches_rule(candidate: dict, rule_str: str) -> bool:
    """
    Evaluate if candidate asset matches a single rule definition.
    """
    rule = _parse_asset(rule_str)
    if not rule.get("valid"):
        return False

    # 1. CIDR Network Rule vs Candidate IP or resolved IPs
    if rule.get("is_network"):
        cand_ip = candidate.get("ip")
        if cand_ip:
            return cand_ip in rule["network"]
        for raw_ip in candidate.get("resolved_ips") or ():
            try:
                ip_obj = (
                    raw_ip
                    if isinstance(raw_ip, (ipaddress.IPv4Address, ipaddress.IPv6Address))
                    else ipaddress.ip_address(str(raw_ip))
                )
                if ip_obj in rule["network"]:
                    return True
            except ValueError:
                continue
        return False

    cand_host = candidate.get("hostname", "")
    rule_host = rule.get("hostname", "")

    # 2. Hostname/IP comparison with loopback aliasing
    host_match = False
    if cand_host and rule_host:
        if cand_host == rule_host:
            host_match = True
        elif cand_host in LOOPBACK_HOSTS and rule_host in LOOPBACK_HOSTS:
            host_match = True
        elif rule_host.startswith("*."):
            domain_suffix = rule_host[2:]
            if cand_host == domain_suffix or cand_host.endswith("." + domain_suffix):
                host_match = True

    if not host_match and rule_host:
        return False

    # 3. Port check: if rule explicitly specifies a port, candidate must match that port
    if rule.get("port") is not None:
        if candidate.get("port") != rule.get("port"):
            return False

    # 4. Path prefix check: if rule specifies a path beyond root, candidate path must start with it
    rule_path = (rule.get("path") or "").rstrip("/")
    if rule_path:
        cand_path = candidate.get("path") or ""
        if not (cand_path == rule_path or cand_path.startswith(rule_path + "/")):
            return False

    return True


def is_asset_in_scope(
    asset: str,
    base_url: str,
    scope_items: Sequence[ScopeItem] = (),
) -> Tuple[bool, str]:
    """
    Pure validation function checking if candidate asset is authorized.

    Evaluation Order:
    1. Out-of-Scope (blacklist) items have top priority: any match immediately blocks.
    2. In-Scope (whitelist) items match next.
    3. Target base_url matches third.
    4. If none matched, asset is considered out-of-scope.
    """
    if not asset or not asset.strip():
        return False, "Asset cannot be empty"

    candidate = _parse_asset(asset)
    if not candidate.get("valid"):
        return False, f"Invalid asset format: '{asset}'"

    # Step 1: Check Out-of-Scope restrictions (Blacklist first)
    for item in scope_items:
        if not item.in_scope:
            if _matches_rule(candidate, item.asset):
                return False, f"Asset matches explicit out-of-scope restriction: '{item.asset}'"

    # Step 2: Check In-Scope items (Whitelist)
    for item in scope_items:
        if item.in_scope:
            if _matches_rule(candidate, item.asset):
                return True, f"Asset authorized by scope rule: '{item.asset}'"

    # Step 3: Check Base URL match
    if base_url:
        if _matches_rule(candidate, base_url):
            return True, f"Asset authorized by target base URL: '{base_url}'"

    return False, f"Asset '{asset}' is not authorized in scope"


class ScopeManager:
    """
    Scope enforcement manager.

    IMPORTANT ARCHITECTURE RULE:
    EVERY scan execution (recon, web_assessment, custom runners) MUST call
    `ScopeManager.assert_in_scope(target_id, asset)` BEFORE initiating any network activity.
    If the asset is out of scope or not explicitly allowed, a ScopeViolationException is raised.
    Recon and web assessment modules depend on this enforcement via the Targets public API.
    """

    def __init__(self, db: Session):
        self.db = db

    def check_scope(self, target_id: uuid.UUID, asset: str) -> Tuple[bool, str]:
        """
        Check if an asset is in scope for the given target, returning (is_in_scope, reason).
        """
        target = self.db.query(Target).filter(Target.id == target_id).first()
        if not target:
            raise NotFoundException(resource="Target", identifier=target_id)

        return is_asset_in_scope(
            asset=asset,
            base_url=target.base_url,
            scope_items=target.scope_items,
        )

    def assert_in_scope(self, target_id: uuid.UUID, asset: str) -> bool:
        """
        Verify that an asset is explicitly authorized and in-scope for the target.

        Raises:
            NotFoundException: if target does not exist.
            ScopeViolationException: if asset is not authorized or explicitly marked out-of-scope.
        Returns:
            True if authorization passes.
        """
        in_scope, reason = self.check_scope(target_id, asset)
        if not in_scope:
            raise ScopeViolationException(asset=asset, target_id=target_id)
        return True

    def _is_ip_explicitly_in_scope(
        self,
        ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address,
        port: Optional[int],
        base_url: str,
        scope_items: Sequence[ScopeItem],
    ) -> bool:
        """Return True if an IP is explicitly authorized by an in-scope rule or target base_url."""
        ip_candidate = {
            "raw": str(ip_obj),
            "valid": True,
            "hostname": str(ip_obj).lower(),
            "port": port,
            "path": "",
            "ip": ip_obj,
            "resolved_ips": [ip_obj],
            "is_network": False,
        }
        for item in scope_items:
            if item.in_scope:
                rule = _parse_asset(item.asset)
                if rule.get("valid") and _matches_rule(ip_candidate, item.asset):
                    return True

        if base_url:
            base_rule = _parse_asset(base_url)
            if base_rule.get("valid"):
                # Match host/IP/port against base_url without requiring a URL path match
                base_host = base_rule.get("hostname", "")
                cand_host = str(ip_obj).lower()
                host_match = (
                    cand_host == base_host
                    or (cand_host in LOOPBACK_HOSTS and base_host in LOOPBACK_HOSTS)
                )
                if host_match:
                    if base_rule.get("port") is None or base_rule.get("port") == port:
                        return True
        return False

    def resolve_and_authorize(
        self,
        target_id: uuid.UUID,
        host: str,
        port: Optional[int] = None,
    ) -> List[str]:
        """
        Resolve all A/AAAA records for host once and validate every resolved IP.

        Fails closed on DNS errors, empty results, out-of-scope IPs/CIDRs,
        or forbidden IP ranges (loopback, link-local, multicast, unspecified;
        private ranges only allowed if explicitly in scope).
        """
        target = self.db.query(Target).filter(Target.id == target_id).first()
        if not target:
            raise NotFoundException(resource="Target", identifier=target_id)

        clean_host = (host or "").strip().strip("[]")
        if not clean_host:
            raise ScopeViolationException(asset=host or "", target_id=target_id)

        try:
            addrinfo = socket.getaddrinfo(
                clean_host,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
        except (socket.gaierror, OSError, ValueError):
            raise ScopeViolationException(asset=clean_host, target_id=target_id)

        resolved_ips: List[str] = []
        seen_ips: set[str] = set()
        for family, _, _, _, sockaddr in addrinfo:
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            raw_ip = sockaddr[0].split("%")[0]
            try:
                ip_obj = ipaddress.ip_address(raw_ip)
            except ValueError:
                raise ScopeViolationException(asset=raw_ip, target_id=target_id)

            normalized = str(ip_obj)
            if normalized not in seen_ips:
                seen_ips.add(normalized)
                resolved_ips.append(normalized)

        if not resolved_ips:
            raise ScopeViolationException(asset=clean_host, target_id=target_id)

        for ip_str in resolved_ips:
            ip_obj = ipaddress.ip_address(ip_str)
            ip_candidate = {
                "raw": ip_str,
                "valid": True,
                "hostname": ip_str.lower(),
                "port": port,
                "path": "",
                "ip": ip_obj,
                "resolved_ips": [ip_obj],
                "is_network": False,
            }

            # 1. Explicit out-of-scope IP/CIDR restrictions always win
            for item in target.scope_items:
                if not item.in_scope and _matches_rule(ip_candidate, item.asset):
                    raise ScopeViolationException(asset=ip_str, target_id=target_id)

            # 2. Always reject link-local (incl. 169.254.169.254), multicast, unspecified
            if ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
                raise ScopeViolationException(asset=ip_str, target_id=target_id)

            # 3. Loopback and private ranges are allowed only if explicitly in scope
            if ip_obj.is_loopback or ip_obj.is_private:
                if not self._is_ip_explicitly_in_scope(
                    ip_obj=ip_obj,
                    port=port,
                    base_url=target.base_url,
                    scope_items=target.scope_items,
                ):
                    raise ScopeViolationException(asset=ip_str, target_id=target_id)

        return resolved_ips


def validate_scope(target_id: uuid.UUID, asset: str, db: Session) -> bool:
    """
    Standalone helper function for scanners and middleware to block unauthorized scan requests
    before hitting any external network.
    """
    manager = ScopeManager(db)
    return manager.assert_in_scope(target_id, asset)
