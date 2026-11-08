"""LLM client wrapper stub."""
from typing import Optional
from app.core.config import settings


class LLMClient:
    """Client for external generative AI APIs (e.g. Anthropic Claude)."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.ANTHROPIC_API_KEY

    def complete(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        # TODO: Implement API call to LLM provider
        raise NotImplementedError("LLM client execution not yet implemented")
