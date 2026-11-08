"""ZAP output parser stub."""
from typing import List, Dict, Any


class ZapParser:
    """Parses ZAP alert JSON outputs into normalized candidate findings."""

    def parse_alerts(self, alerts_json: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # TODO: Parse ZAP alerts to standard finding candidates
        return []
