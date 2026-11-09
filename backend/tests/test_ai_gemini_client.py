"""Tests for the Gemini client wrapper, outbound boundaries, and failure modes."""
import ast
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from app.core.config import settings
from app.core.exceptions import (
    ServiceUnavailableException,
    RateLimitException,
    BadGatewayException,
)
from app.modules.ai_analysis.redaction import redact_text
from app.modules.ai_analysis.gemini_client import call_gemini_api
from app.modules.ai_analysis.schemas import ScanInterpretationResponse


def test_reject_unredacted_input_type_check():
    """Prove the single outbound function rejects raw strings or unredacted inputs."""
    with pytest.raises(TypeError, match="Unredacted input rejected"):
        call_gemini_api(
            redacted_input="This is a raw unredacted string",  # Not a RedactedText
            system_instruction="System prompt",
            prompt_content="Prompt content",
            response_schema=ScanInterpretationResponse,
        )


def test_ast_only_gemini_client_imports_genai_sdk():
    """
    Statically inspects all files under app/ using AST.
    Enforces architectural security invariant:
    ONLY app/modules/ai_analysis/gemini_client.py is permitted to import google.genai.
    """
    app_dir = Path(__file__).resolve().parent.parent / "app"
    assert app_dir.exists() and app_dir.is_dir()

    allowed_file = app_dir / "modules" / "ai_analysis" / "gemini_client.py"
    violations = []

    for py_file in app_dir.rglob("*.py"):
        if py_file.resolve() == allowed_file.resolve():
            continue

        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if "genai" in alias.name or "google.genai" in alias.name:
                        violations.append(f"{py_file.relative_to(app_dir)}: imports {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if node.module and ("genai" in node.module or "google.genai" in node.module):
                    violations.append(f"{py_file.relative_to(app_dir)}: imports from {node.module}")

    assert not violations, "Forbidden Gemini SDK imports detected outside gemini_client.py:\n" + "\n".join(violations)


def test_missing_api_key_or_disabled_raises_service_unavailable(monkeypatch):
    monkeypatch.setattr(settings, "AI_ENABLED", False)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "")

    redacted = redact_text("sample content")
    with pytest.raises(ServiceUnavailableException, match="AI features are disabled or GEMINI_API_KEY is not configured"):
        call_gemini_api(
            redacted_input=redacted,
            system_instruction="sys",
            prompt_content="prompt",
            response_schema=ScanInterpretationResponse,
        )


@patch("app.modules.ai_analysis.gemini_client._get_genai_client")
def test_transient_rate_limit_and_retry(mock_get_client, monkeypatch):
    """Test 429 transient rate-limit retries up to max_retries with backoff."""
    monkeypatch.setattr(settings, "AI_ENABLED", True)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "test_mock_api_key")
    monkeypatch.setattr(settings, "AI_MAX_RETRIES", 1)

    from google.genai.errors import APIError

    mock_client = MagicMock()
    # Simulate APIError 429
    err = APIError(code=429, response_json={"error": "Resource exhausted"})
    err.message = "Resource exhausted"
    mock_client.models.generate_content.side_effect = err
    mock_get_client.return_value = mock_client

    redacted = redact_text("sample target banner")
    with pytest.raises(RateLimitException, match="rate limit or quota exceeded"):
        call_gemini_api(
            redacted_input=redacted,
            system_instruction="sys",
            prompt_content="prompt",
            response_schema=ScanInterpretationResponse,
        )

    assert mock_client.models.generate_content.call_count == 2


@patch("app.modules.ai_analysis.gemini_client._get_genai_client")
def test_safety_filter_blocked_response(mock_get_client, monkeypatch):
    monkeypatch.setattr(settings, "AI_ENABLED", True)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "test_mock_api_key")

    mock_client = MagicMock()
    candidate = MagicMock()
    candidate.finish_reason = "SAFETY"
    mock_response = MagicMock()
    mock_response.candidates = [candidate]
    mock_client.models.generate_content.return_value = mock_response
    mock_get_client.return_value = mock_client

    redacted = redact_text("sample target text")
    with pytest.raises(BadGatewayException, match="safety filters"):
        call_gemini_api(
            redacted_input=redacted,
            system_instruction="sys",
            prompt_content="prompt",
            response_schema=ScanInterpretationResponse,
        )


@patch("app.modules.ai_analysis.gemini_client._get_genai_client")
def test_empty_response_handling(mock_get_client, monkeypatch):
    monkeypatch.setattr(settings, "AI_ENABLED", True)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "test_mock_api_key")

    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.candidates = []
    mock_client.models.generate_content.return_value = mock_response
    mock_get_client.return_value = mock_client

    redacted = redact_text("sample target text")
    with pytest.raises(BadGatewayException, match="empty response"):
        call_gemini_api(
            redacted_input=redacted,
            system_instruction="sys",
            prompt_content="prompt",
            response_schema=ScanInterpretationResponse,
        )


@patch("app.modules.ai_analysis.gemini_client._get_genai_client")
def test_schema_validation_failure_and_repair_attempt(mock_get_client, monkeypatch):
    monkeypatch.setattr(settings, "AI_ENABLED", True)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "test_mock_api_key")

    mock_client = MagicMock()
    # Call 1 returns invalid json, call 2 (repair) returns valid json
    resp1 = MagicMock()
    resp1.candidates = [MagicMock(finish_reason="STOP")]
    resp1.text = '{"summary": "Incomplete data"}'
    resp1.usage_metadata = None

    valid_fixture = Path(__file__).parent / "fixtures" / "ai" / "sample_interpret_response.json"
    resp2 = MagicMock()
    resp2.candidates = [MagicMock(finish_reason="STOP")]
    resp2.text = valid_fixture.read_text(encoding="utf-8")
    resp2.usage_metadata = None

    mock_client.models.generate_content.side_effect = [resp1, resp2]
    mock_get_client.return_value = mock_client

    redacted = redact_text("sample target text")
    parsed, data, in_t, out_t, lat = call_gemini_api(
        redacted_input=redacted,
        system_instruction="sys",
        prompt_content="prompt",
        response_schema=ScanInterpretationResponse,
    )

    assert isinstance(parsed, ScanInterpretationResponse)
    assert parsed.summary is not None
    assert mock_client.models.generate_content.call_count == 2
