import uuid
from fastapi.testclient import TestClient


def test_targets_crud_lifecycle(client: TestClient):
    """Test full CRUD lifecycle for Targets and Scope items."""
    # 1. Create Target with initial scope item
    target_payload = {
        "name": f"Test Local App {uuid.uuid4().hex[:6]}",
        "base_url": "http://localhost:3000",
        "description": "Authorized local target for automated scanner tests",
        "authorization_note": "Approved in testing environment",
        "scope_items": [
            {
                "asset": "http://localhost:3000/api",
                "in_scope": True,
                "notes": "Backend API endpoints",
            },
            {
                "asset": "http://localhost:3000/admin",
                "in_scope": False,
                "notes": "Admin panel explicitly excluded",
            },
        ],
    }

    create_res = client.post("/api/v1/targets/", json=target_payload)
    assert create_res.status_code == 201, create_res.text
    target_data = create_res.json()
    target_id = target_data["id"]
    assert target_data["name"] == target_payload["name"]
    assert target_data["base_url"] == "http://localhost:3000"
    assert len(target_data["scope_items"]) == 2

    # 2. Verify dual route compatibility (/api/targets and /api/v1/targets)
    compat_res = client.get("/api/targets/")
    assert compat_res.status_code == 200
    all_targets = compat_res.json()
    assert any(t["id"] == target_id for t in all_targets)

    # 3. Read Target by ID
    get_res = client.get(f"/api/v1/targets/{target_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == target_id

    # 4. Patch Target metadata
    patch_res = client.patch(
        f"/api/v1/targets/{target_id}",
        json={"description": "Updated description for test target"},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["description"] == "Updated description for test target"

    # 5. List Scope Items
    scope_res = client.get(f"/api/v1/targets/{target_id}/scope")
    assert scope_res.status_code == 200
    scope_list = scope_res.json()
    assert len(scope_list) == 2

    # 6. Add a new Scope Item
    new_scope_item = {
        "asset": "127.0.0.1:3000",
        "in_scope": True,
        "notes": "Loopback direct alias",
    }
    add_scope_res = client.post(f"/api/v1/targets/{target_id}/scope", json=new_scope_item)
    assert add_scope_res.status_code == 201
    created_item_id = add_scope_res.json()["id"]

    # 7. Validate Scope through API
    # 7a. In-scope asset
    val_allowed = client.post(
        f"/api/v1/targets/{target_id}/scope/validate",
        json={"asset": "http://localhost:3000/api/v1/items"},
    )
    assert val_allowed.status_code == 200
    assert val_allowed.json()["in_scope"] is True

    # 7b. Out-of-scope asset (admin excluded)
    val_blocked = client.post(
        f"/api/v1/targets/{target_id}/scope/validate",
        json={"asset": "http://localhost:3000/admin/settings"},
    )
    assert val_blocked.status_code == 200
    assert val_blocked.json()["in_scope"] is False

    # 7c. External unauthorized asset
    val_external = client.post(
        f"/api/v1/targets/{target_id}/scope/validate",
        json={"asset": "http://evil-external-host.com"},
    )
    assert val_external.status_code == 200
    assert val_external.json()["in_scope"] is False

    # 8. Delete added scope item
    del_scope_res = client.delete(f"/api/v1/targets/{target_id}/scope/{created_item_id}")
    assert del_scope_res.status_code == 204

    # 9. Delete target
    del_target_res = client.delete(f"/api/v1/targets/{target_id}")
    assert del_target_res.status_code == 204

    # Verify target is now deleted
    get_after_del = client.get(f"/api/v1/targets/{target_id}")
    assert get_after_del.status_code == 404

