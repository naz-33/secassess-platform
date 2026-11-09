"""Backward compatibility shim delegating to gemini_client."""
from app.modules.ai_analysis.gemini_client import call_gemini_api

__all__ = ["call_gemini_api"]
