import socket
import uuid
from unittest.mock import patch
import pytest
from app.core.exceptions import NotFoundException, ScopeViolationException
from app.modules.targets.models import ScopeItem
from app.modules.targets.scope_manager import (
    is_asset_in_scope,
    ScopeManager,
    validate_scope,
)
from app.core.database import SessionLocal
from app.modules.targets import TargetService
from app.modules.targets.schemas import ScopeItemCreate, TargetCreate


def test_is_asset_in_scope_base_url():
    """Verify base_url matching including localhost and loopback variations."""
    base_url = "http://localhost:3000"

    # Authorized assets
    ok, _ = is_asset_in_scope("http://localhost:3000", base_url)
    assert ok is True

    ok, _ = is_asset_in_scope("http://localhost:3000/api/v1/users", base_url)
    assert ok is True

    ok, _ = is_asset_in_scope("http://127.0.0.1:3000", base_url)
    assert ok is True

    ok, _ = is_asset_in_scope("localhost:3000", base_url)
    assert ok is True

    # Unauthorized assets
    ok, _ = is_asset_in_scope("http://localhost:8080", base_url)
    assert ok is False

    ok, _ = is_asset_in_scope("http://192.168.1.50:3000", base_url)
    assert ok is False

    ok, _ = is_asset_in_scope("https://google.com", base_url)
    assert ok is False


def test_is_asset_in_scope_cidr_rule():
    """Verify CIDR notation scope item matching."""
    base_url = "http://juice-shop:3000"
    scope_items = [
        ScopeItem(
            id=uuid.uuid4(),
            target_id=uuid.uuid4(),
            asset="192.168.1.0/24",
            in_scope=True,
            notes="Internal assessment subnet",
        )
    ]

    ok, _ = is_asset_in_scope("192.168.1.15", base_url, scope_items)
    assert ok is True

    ok, _ = is_asset_in_scope("http://192.168.1.42:8000", base_url, scope_items)
    assert ok is True

    ok, _ = is_asset_in_scope("192.168.2.15", base_url, scope_items)
    assert ok is False


def test_is_asset_in_scope_wildcard_domain():
    """Verify wildcard domain scope item matching."""
    base_url = "https://example.com"
    scope_items = [
        ScopeItem(
            id=uuid.uuid4(),
            target_id=uuid.uuid4(),
            asset="*.example.com",
            in_scope=True,
            notes="Subdomain wildcards",
        )
    ]

    ok, _ = is_asset_in_scope("https://api.example.com", base_url, scope_items)
    assert ok is True

    ok, _ = is_asset_in_scope("https://auth.stage.example.com/login", base_url, scope_items)
    assert ok is True

    ok, _ = is_asset_in_scope("https://attacker.com", base_url, scope_items)
    assert ok is False


def test_is_asset_in_scope_blacklist_precedence():
    """Verify out-of-scope restriction overrides base URL and whitelist rules."""
    base_url = "http://localhost:3000"
    scope_items = [
        ScopeItem(
            id=uuid.uuid4(),
            target_id=uuid.uuid4(),
            asset="http://localhost:3000/admin",
            in_scope=False,
            notes="Out-of-scope admin portal",
        ),
        ScopeItem(
            id=uuid.uuid4(),
            target_id=uuid.uuid4(),
            asset="http://localhost:3000/api",
            in_scope=True,
            notes="In-scope API",
        ),
    ]

    # Authorized endpoint
    ok, _ = is_asset_in_scope("http://localhost:3000/api/users", base_url, scope_items)
    assert ok is True

    # Blocked endpoint due to explicit out-of-scope blacklist rule
    ok, reason = is_asset_in_scope("http://localhost:3000/admin", base_url, scope_items)
    assert ok is False
    assert "out-of-scope restriction" in reason

    ok, reason = is_asset_in_scope("http://localhost:3000/admin/keys", base_url, scope_items)
    assert ok is False
    assert "out-of-scope restriction" in reason


def test_scope_manager_db_enforcement(admin_user):
    """Verify ScopeManager and validate_scope integration with DB."""
    db = SessionLocal()
    try:
        manager = ScopeManager(db)
        target = TargetService(db).create_target(
            TargetCreate(
                name=f"Scope Manager Target {uuid.uuid4().hex[:8]}",
                base_url="http://juice-shop:3000",
                scope_items=[
                    ScopeItemCreate(
                        asset="http://juice-shop:3000",
                        in_scope=True,
                    )
                ],
            ), user_id=admin_user.id
        )

        # Valid in-scope asset
        assert manager.assert_in_scope(target.id, "http://juice-shop:3000") is True
        assert validate_scope(target.id, "http://juice-shop:3000/rest/products", db) is True

        # Unauthorized asset raises ScopeViolationException
        with pytest.raises(ScopeViolationException):
            manager.assert_in_scope(target.id, "http://unauthorized-external-server.com")

        # Unknown target raises NotFoundException
        with pytest.raises(NotFoundException):
            manager.assert_in_scope(uuid.uuid4(), "http://localhost:3000")
    finally:
        db.close()


def _fake_addrinfo(*ips: str):
    results = []
    for ip in ips:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sockaddr = (ip, 443, 0, 0) if family == socket.AF_INET6 else (ip, 443)
        results.append((family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr))
    return results


def test_matches_rule_cidr_against_resolved_ips():
    """_matches_rule checks CIDR rules against resolved_ips, not just IP literals."""
    from app.modules.targets.scope_manager import _matches_rule

    candidate = {
        "raw": "internal.example.com",
        "valid": True,
        "hostname": "internal.example.com",
        "port": 443,
        "path": "",
        "ip": None,
        "resolved_ips": ["10.20.30.40"],
        "is_network": False,
    }
    assert _matches_rule(candidate, "10.20.0.0/16") is True
    assert _matches_rule(candidate, "192.168.0.0/16") is False


def test_resolve_and_authorize_rejects_out_of_scope_and_forbidden_ips(admin_user):
    """Hostname resolving to out-of-scope CIDR or forbidden ranges is rejected."""
    db = SessionLocal()
    try:
        manager = ScopeManager(db)
        target = TargetService(db).create_target(
            TargetCreate(
                name=f"DNS Scope Target {uuid.uuid4().hex[:8]}",
                base_url="https://app.example.com",
                scope_items=[
                    ScopeItemCreate(asset="203.0.113.0/24", in_scope=False),
                ],
            ), user_id=admin_user.id
        )

        # Public IP is allowed
        with patch("socket.getaddrinfo", return_value=_fake_addrinfo("93.184.216.34")):
            assert manager.resolve_and_authorize(target.id, "app.example.com", 443) == ["93.184.216.34"]

        # Blacklisted CIDR, loopback, link-local (169.254.169.254), multicast, unspecified, private
        for bad_ip in (
            "203.0.113.10",
            "127.0.0.1",
            "169.254.169.254",
            "224.0.0.1",
            "0.0.0.0",
            "10.0.0.5",
        ):
            with patch("socket.getaddrinfo", return_value=_fake_addrinfo(bad_ip)):
                with pytest.raises(ScopeViolationException):
                    manager.resolve_and_authorize(target.id, "app.example.com", 443)
    finally:
        db.close()


def test_resolve_and_authorize_allows_explicitly_in_scope_private_range(admin_user):
    """Private ranges are allowed only if explicitly in scope (e.g. local Docker target)."""
    db = SessionLocal()
    try:
        manager = ScopeManager(db)
        target = TargetService(db).create_target(
            TargetCreate(
                name=f"Docker Scope Target {uuid.uuid4().hex[:8]}",
                base_url="http://juice-shop:3000",
                scope_items=[
                    ScopeItemCreate(asset="172.18.0.0/16", in_scope=True),
                ],
            ), user_id=admin_user.id
        )

        with patch("socket.getaddrinfo", return_value=_fake_addrinfo("172.18.0.5")):
            assert manager.resolve_and_authorize(target.id, "juice-shop", 3000) == ["172.18.0.5"]
    finally:
        db.close()


def test_resolve_and_authorize_rejects_multi_record_with_one_bad_ip(admin_user):
    """If any resolved IP in a multi-record response is forbidden/out-of-scope, reject all."""
    db = SessionLocal()
    try:
        manager = ScopeManager(db)
        target = TargetService(db).create_target(
            TargetCreate(
                name=f"Multi Record Target {uuid.uuid4().hex[:8]}",
                base_url="https://app.example.com",
            ), user_id=admin_user.id
        )

        with patch(
            "socket.getaddrinfo",
            return_value=_fake_addrinfo("93.184.216.34", "169.254.169.254"),
        ):
            with pytest.raises(ScopeViolationException):
                manager.resolve_and_authorize(target.id, "app.example.com", 443)
    finally:
        db.close()


def test_resolve_and_authorize_ipv6_and_dns_failure(admin_user):
    """Public IPv6 is returned normalized; ::1 for non-loopback target and DNS errors fail closed."""
    db = SessionLocal()
    try:
        manager = ScopeManager(db)
        target = TargetService(db).create_target(
            TargetCreate(
                name=f"IPv6 DNS Target {uuid.uuid4().hex[:8]}",
                base_url="https://app.example.com",
            ), user_id=admin_user.id
        )

        with patch(
            "socket.getaddrinfo",
            return_value=_fake_addrinfo("2606:2800:220:1:248:1893:25c8:1946"),
        ):
            assert manager.resolve_and_authorize(target.id, "app.example.com", 443) == [
                "2606:2800:220:1:248:1893:25c8:1946"
            ]

        with patch("socket.getaddrinfo", return_value=_fake_addrinfo("::1")):
            with pytest.raises(ScopeViolationException):
                manager.resolve_and_authorize(target.id, "app.example.com", 443)

        with patch("socket.getaddrinfo", side_effect=socket.gaierror("DNS lookup failed")):
            with pytest.raises(ScopeViolationException):
                manager.resolve_and_authorize(target.id, "app.example.com", 443)

        with patch("socket.getaddrinfo", return_value=[]):
            with pytest.raises(ScopeViolationException):
                manager.resolve_and_authorize(target.id, "app.example.com", 443)
    finally:
        db.close()
