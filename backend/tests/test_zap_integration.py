import json
import uuid
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
from app.core.config import settings
from app.modules.findings import FindingSeverity
from app.modules.web_assessment.parsers.zap_parser import parse_zap_alerts
from app.modules.web_assessment.runners.zap_runner import ZapRunner

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_parse_zap_alerts_fixture():
    """Verify parse_zap_alerts correctly parses the realistic ZAP alerts fixture."""
    fixture_path = FIXTURES_DIR / "zap_alerts.json"
    alerts_data = json.loads(fixture_path.read_text(encoding="utf-8"))

    candidates = parse_zap_alerts(alerts_data)
    assert len(candidates) == 5

    titles = [c.title for c in candidates]
    assert any("Content Security Policy" in t for t in titles)
    assert any("Anti-clickjacking" in t for t in titles)
    assert any("Cookie No HttpOnly" in t for t in titles)
    assert any("Server Leaks" in t for t in titles)
    assert any("Directory Browsing" in t for t in titles)

    # Check category mappings
    categories = {c.category for c in candidates}
    assert "security_headers" in categories
    assert "session_management" in categories
    assert "information_disclosure" in categories
    assert "exposed_files" in categories

    # Check severities
    csp_cand = next(c for c in candidates if "Content Security Policy" in c.title)
    assert csp_cand.severity == FindingSeverity.MEDIUM
    assert csp_cand.wstg_id == "WSTG-CONF-07"
    assert csp_cand.owasp_top10 == "A05:2021-Security Misconfiguration"
    assert csp_cand.cwe == "CWE-693"
    assert csp_cand.remediation is not None
    assert "Evidence" in csp_cand.evidence_content

    backup_cand = next(c for c in candidates if "Directory Browsing" in c.title)
    assert backup_cand.severity == FindingSeverity.HIGH
    assert backup_cand.cwe == "CWE-548"


def test_zap_unreachable_graceful_failure():
    """When ZAP daemon is unreachable, runner raises ConnectionError with clear message."""
    mock_db = MagicMock()
    runner = ZapRunner(
        db=mock_db,
        target_id=uuid.uuid4(),
        zap_api_url="http://127.0.0.1:9999",  # unroutable / closed port
        timeout=1.0,
    )
    with pytest.raises(ConnectionError) as exc_info:
        runner.check_reachability()
    assert "OWASP ZAP daemon is not reachable" in str(exc_info.value)
    assert "daemon/headless mode with the API enabled" in str(exc_info.value)


def test_zap_active_scan_refused_by_default():
    """Active scan requires explicit ZAP_ALLOW_ACTIVE_SCAN=True and is refused by default."""
    mock_db = MagicMock()
    runner = ZapRunner(db=mock_db, target_id=uuid.uuid4())

    with patch.object(settings, "ZAP_ALLOW_ACTIVE_SCAN", False):
        with pytest.raises(ValueError) as exc_info:
            runner.trigger_active_scan("http://localhost:3000")
        assert "Active scanning in ZAP is disabled by default" in str(exc_info.value)


def test_zap_context_scope_includes_and_excludes():
    """Verify ZAP context configuration generates include regex for target and excludes for out-of-scope."""
    mock_db = MagicMock()
    runner = ZapRunner(db=mock_db, target_id=uuid.uuid4())

    requested_calls = []

    def mock_request(endpoint, params=None):
        requested_calls.append((endpoint, params))
        if "newContext" in endpoint:
            return {"contextId": "42"}
        return {}

    runner._request = mock_request

    context_id = runner.setup_context(
        context_name="test_ctx",
        target_url="http://localhost:3000",
        out_of_scope_assets=["http://localhost:3000/admin", "http://localhost:3000/secret"],
    )
    assert context_id == "42"

    # Verify include call
    includes = [c for c in requested_calls if "includeInContext" in c[0]]
    assert len(includes) == 1
    assert "http://localhost:3000.*" in includes[0][1]["regex"]

    # Verify exclude calls
    excludes = [c for c in requested_calls if "excludeFromContext" in c[0]]
    assert len(excludes) == 2
    assert any("/admin" in c[1]["regex"] for c in excludes)
    assert any("/secret" in c[1]["regex"] for c in excludes)


def test_zap_full_execution_workflow_mock():
    """Complete mocked ZAP execution: version check, spider, passive scan drain, alert retrieval."""
    mock_db = MagicMock()
    runner = ZapRunner(db=mock_db, target_id=uuid.uuid4())

    # Mock scope manager to allow in-scope URLs and block out-of-scope
    runner.scope_manager.check_scope = MagicMock(
        side_effect=lambda tid, url: (False, "Blocked") if "admin" in url else (True, "OK")
    )

    zap_responses = {
        "JSON/core/view/version/": {"version": "2.14.0"},
        "JSON/context/action/newContext/": {"contextId": "1"},
        "JSON/context/action/includeInContext/": {},
        "JSON/context/action/excludeFromContext/": {},
        "JSON/spider/action/scan/": {"scan": "101"},
        "JSON/spider/view/status/": {"status": "100"},
        "JSON/spider/view/results/": {
            "results": [
                "http://localhost:3000/api",
                "http://localhost:3000/about",
                "http://localhost:3000/admin/dashboard",  # out-of-scope!
            ]
        },
        "JSON/pscan/view/recordsToScan/": {"recordsToScan": "0"},
        "JSON/core/view/alerts/": {
            "alerts": [
                {
                    "alert": "Content Security Policy (CSP) Header Not Set",
                    "risk": "Medium",
                    "pluginId": "10038",
                    "url": "http://localhost:3000/",
                }
            ]
        },
    }

    runner._request = MagicMock(side_effect=lambda ep, p=None: zap_responses.get(ep, {}))

    candidates, spidered, raw_json = runner.execute_zap_assessment(
        target_url="http://localhost:3000",
        out_of_scope_assets=["http://localhost:3000/admin"],
        run_active_scan=False,
    )

    assert len(candidates) == 1
    assert candidates[0].title == "[ZAP] Content Security Policy (CSP) Header Not Set"
    # /admin must be filtered out by ScopeManager
    assert len(spidered) == 2
    assert "http://localhost:3000/admin/dashboard" not in spidered
    assert "alerts" in raw_json

