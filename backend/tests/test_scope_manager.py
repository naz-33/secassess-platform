import uuid
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


def test_scope_manager_db_enforcement():
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
            )
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
