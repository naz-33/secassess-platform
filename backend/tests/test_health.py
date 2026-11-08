from fastapi.testclient import TestClient


def test_health_check(client: TestClient):
    """Test that /api/v1/health returns 200 with database connectivity status."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["database"] == "ok"
    assert "version" in data


def test_openapi_docs_available(client: TestClient):
    """Test that OpenAPI documentation is available and lists module endpoints."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert "paths" in schema
    paths = schema["paths"]

    # Verify every module has at least one mounted endpoint under /api/v1
    expected_prefixes = [
        "/api/v1/auth",
        "/api/v1/audit",
        "/api/v1/targets",
        "/api/v1/assessments",
        "/api/v1/scans",
        "/api/v1/recon",
        "/api/v1/web-assessment",
        "/api/v1/findings",
        "/api/v1/ai-analysis",
        "/api/v1/verification",
        "/api/v1/reports",
        "/api/v1/dashboard",
    ]
    for prefix in expected_prefixes:
        assert any(p.startswith(prefix) for p in paths), f"Expected endpoint matching prefix: {prefix}"
