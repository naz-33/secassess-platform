"""Base tool adapter interface for security scanner execution."""
from abc import ABC, abstractmethod
from typing import List, Dict, Any


class ToolAdapter(ABC):
    """Abstract base class for all pluggable scanner execution adapters."""

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Identifier of the tool (e.g. 'nmap', 'dns', 'zap', 'curl')."""
        pass

    @abstractmethod
    def build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        """
        Build an argument vector (argv list) for safe subprocess execution.
        Must enforce strict option allow-listing.
        """
        pass

    @abstractmethod
    def parse(self, raw_output: str) -> List[Dict[str, Any]]:
        """
        Parse raw stdout/output into structured asset items.
        Each item is a dict with keys: type (host/port/service/endpoint), value, details.
        """
        pass

