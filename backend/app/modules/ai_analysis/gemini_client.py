"""Google Gemini API client wrapper module.

This is the SOLE module in the application permitted to import the Google GenAI SDK.
It enforces strict type safety: outbound prompts are rejected unless wrapped in RedactedText.
"""
import json
import logging
import time
from typing import TypeVar, Type, Tuple, Dict, Any
from pydantic import BaseModel, ValidationError

# The Google Gen AI Python SDK (google-genai>=3.0.0)
from google import genai
from google.genai import types
from google.genai.errors import APIError

from app.core.config import settings
from app.core.exceptions import (
    ServiceUnavailableException,
    RateLimitException,
    BadGatewayException,
    UnprocessableEntityException,
)
from app.modules.ai_analysis.redaction import RedactedText

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


def _get_genai_client() -> genai.Client:
    """Instantiate and configure GenAI client from settings."""
    if not settings.AI_ENABLED or not settings.GEMINI_API_KEY or not settings.GEMINI_API_KEY.strip():
        raise ServiceUnavailableException("AI features are disabled or GEMINI_API_KEY is not configured.")

    return genai.Client(api_key=settings.GEMINI_API_KEY)


def call_gemini_api(
    redacted_input: RedactedText,
    system_instruction: str,
    prompt_content: str,
    response_schema: Type[T],
) -> Tuple[T, Dict[str, Any], int, int, int]:
    """
    Sole sanctioned outbound function executing inference via the Google Gemini API.

    Safety Guarantee:
        Strictly enforces that dynamic prompt content is encapsulated in a RedactedText
        wrapper. Passing an unredacted string or arbitrary type raises TypeError.

    Returns:
        Tuple of (parsed_pydantic_model, response_dict, input_tokens, output_tokens, latency_ms)

    Raises:
        TypeError: If redacted_input is not an instance of RedactedText.
        ServiceUnavailableException: If AI is disabled or API key missing.
        RateLimitException: If 429 quota or rate limits are reached.
        BadGatewayException: On safety filter blocks, provider errors, or empty responses.
        UnprocessableEntityException: If the response fails schema validation after repair attempt.
    """
    # 1. Strict type check: Enforce RedactedText boundary
    if not isinstance(redacted_input, RedactedText):
        raise TypeError(
            "Unredacted input rejected: Dynamic prompt context must be passed as a RedactedText instance."
        )

    client = _get_genai_client()

    # 2. Configure structured output generation
    config = types.GenerateContentConfig(
        system_instruction=system_instruction,
        response_mime_type="application/json",
        response_schema=response_schema,
        temperature=settings.AI_TEMPERATURE,
        max_output_tokens=settings.AI_MAX_OUTPUT_TOKENS,
    )

    max_retries = max(0, settings.AI_MAX_RETRIES)
    attempt = 0
    start_time = time.perf_counter()

    while attempt <= max_retries:
        try:
            logger.info(
                "Calling Gemini API (model=%s, attempt=%d/%d)",
                settings.GEMINI_MODEL,
                attempt + 1,
                max_retries + 1,
            )

            response = client.models.generate_content(
                model=settings.GEMINI_MODEL,
                contents=prompt_content,
                config=config,
            )

            latency_ms = int((time.perf_counter() - start_time) * 1000)

            # Check for safety filter blocks or empty candidates
            if not response.candidates or len(response.candidates) == 0:
                raise BadGatewayException("Gemini returned an empty response candidate set.")

            primary_candidate = response.candidates[0]
            finish_reason = getattr(primary_candidate, "finish_reason", None)
            finish_reason_str = str(finish_reason).upper() if finish_reason else ""
            if "SAFETY" in finish_reason_str or "BLOCKED" in finish_reason_str:
                raise BadGatewayException("AI generation was blocked by safety filters.")

            raw_text = response.text
            if not raw_text or not raw_text.strip():
                raise BadGatewayException("AI provider returned an empty response payload.")

            # Extract token metrics if available
            input_tokens = 0
            output_tokens = 0
            if response.usage_metadata:
                input_tokens = getattr(response.usage_metadata, "prompt_token_count", 0) or 0
                output_tokens = getattr(response.usage_metadata, "candidates_token_count", 0) or 0

            # 3. Validate against Pydantic schema
            parsed_model, response_dict = _validate_or_repair_response(
                client=client,
                raw_text=raw_text,
                response_schema=response_schema,
                system_instruction=system_instruction,
            )

            return parsed_model, response_dict, input_tokens, output_tokens, latency_ms

        except (ServiceUnavailableException, TypeError):
            # Non-transient errors: do not retry
            raise

        except APIError as api_err:
            status_code = getattr(api_err, "code", None)
            provider_message = api_err.message
            if settings.GEMINI_API_KEY:
                provider_message = provider_message.replace(
                    settings.GEMINI_API_KEY, "[REDACTED_API_KEY]"
                )
            logger.warning("Gemini API error (code=%s): %s", status_code, provider_message)
            if status_code == 429:
                if attempt < max_retries:
                    time.sleep(0.5 * (2 ** attempt))
                    attempt += 1
                    continue
                raise RateLimitException("Gemini API rate limit or quota exceeded.")
            elif status_code and 500 <= status_code < 600:
                if attempt < max_retries:
                    time.sleep(0.5 * (2 ** attempt))
                    attempt += 1
                    continue
                raise BadGatewayException(f"Gemini API upstream error ({status_code}).")
            else:
                raise BadGatewayException(f"Gemini API error: {provider_message}")

        except Exception as exc:
            # Handle transient socket/connection errors
            err_str = str(exc).lower()
            safe_message = str(exc)
            if settings.GEMINI_API_KEY:
                safe_message = safe_message.replace(settings.GEMINI_API_KEY, "[REDACTED_API_KEY]")
            if any(term in err_str for term in ("timeout", "timed out", "connection", "retry")):
                if attempt < max_retries:
                    time.sleep(0.5 * (2 ** attempt))
                    attempt += 1
                    continue
                raise BadGatewayException(f"Gemini request timed out: {safe_message}")
            raise


def _validate_or_repair_response(
    client: genai.Client,
    raw_text: str,
    response_schema: Type[T],
    system_instruction: str,
) -> Tuple[T, Dict[str, Any]]:
    """Validate model output against response_schema, attempting one schema repair if malformed."""
    parse_err_msg = ""
    # Attempt 1: Direct validation
    try:
        data = json.loads(raw_text)
        validated = response_schema.model_validate(data)
        return validated, data
    except (json.JSONDecodeError, ValidationError) as parse_err:
        parse_err_msg = str(parse_err)
        logger.warning("Initial AI response failed schema validation: %s. Attempting repair...", parse_err)

    # Attempt 2: Schema repair prompt
    repair_prompt = (
        "The following JSON payload failed schema validation against the required JSON schema:\n"
        f"```json\n{raw_text}\n```\n"
        f"Error details:\n{parse_err_msg}\n"
        "Please fix the formatting, types, or missing keys and return strictly valid JSON conforming to the schema."
    )
    try:
        repair_config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            response_mime_type="application/json",
            response_schema=response_schema,
            temperature=0.0,
            max_output_tokens=settings.AI_MAX_OUTPUT_TOKENS,
        )
        repaired_resp = client.models.generate_content(
            model=settings.GEMINI_MODEL,
            contents=repair_prompt,
            config=repair_config,
        )
        if repaired_resp.text:
            repaired_data = json.loads(repaired_resp.text)
            validated = response_schema.model_validate(repaired_data)
            return validated, repaired_data
    except Exception as repair_fail:
        logger.error("AI output repair attempt failed: %s", repair_fail)

    raise UnprocessableEntityException("AI output failed JSON schema validation and could not be repaired.")
