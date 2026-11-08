"""OWASP ZAP runner stub."""


class ZapRunner:
    """Wrapper for initiating and polling OWASP ZAP active / passive scans."""

    def run_scan(self, target_url: str) -> dict:
        # TODO: Trigger OWASP ZAP API scan on verified target URL
        raise NotImplementedError("ZAP scan execution not yet implemented")
