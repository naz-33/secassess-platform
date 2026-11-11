import json
from typing import List, Dict, Any, Union
from app.modules.findings import FindingSeverity
from app.modules.web_assessment.types import CandidateFinding

ZAP_RISK_MAP = {
    "0": FindingSeverity.INFO,
    "informational": FindingSeverity.INFO,
    "info": FindingSeverity.INFO,
    "1": FindingSeverity.LOW,
    "low": FindingSeverity.LOW,
    "2": FindingSeverity.MEDIUM,
    "medium": FindingSeverity.MEDIUM,
    "3": FindingSeverity.HIGH,
    "high": FindingSeverity.HIGH,
    "critical": FindingSeverity.CRITICAL,
}
MAX_EVIDENCE_URLS = 20


def map_zap_category(alert_name: str, plugin_id: str) -> str:
    """Map ZAP alert title and pluginId to one of the 4 project categories or other."""
    name_lower = alert_name.lower()
    pid = str(plugin_id).strip()

    # Security Headers & HTTPS
    if any(k in name_lower for k in ("content security policy", "csp", "x-frame", "x-content-type", "strict-transport", "hsts", "cors", "referrer-policy", "permissions-policy")):
        return "security_headers"
    if pid in ("10038", "10020", "10021", "10035", "10063", "90003"):
        return "security_headers"

    # Exposed files & directories
    if any(k in name_lower for k in ("backup", "directory browsing", "git", "env", "robots.txt", "sitemap", "source code disclosure", "hidden file")):
        return "exposed_files"
    if pid in ("10095", "10045", "40018", "40028"):
        return "exposed_files"

    # Information disclosure
    if any(k in name_lower for k in ("server leaks", "information disclosure", "debug", "error message", "stack trace", "banner")):
        return "information_disclosure"
    if pid in ("10036", "10037", "10023", "10055"):
        return "information_disclosure"

    # Session management
    if any(k in name_lower for k in ("cookie", "session", "httponly", "samesite", "secure flag")):
        return "session_management"
    if pid in ("10010", "10011", "10054", "10029"):
        return "session_management"

    return "other"


def map_zap_wstg_and_owasp(category: str) -> tuple[str, str]:
    """Map category to corresponding WSTG ID and OWASP Top 10 identifier."""
    if category == "security_headers":
        return "WSTG-CONF-07", "A05:2021-Security Misconfiguration"
    elif category == "exposed_files":
        return "WSTG-CONF-04", "A05:2021-Security Misconfiguration"
    elif category == "information_disclosure":
        return "WSTG-INFO-02", "A05:2021-Security Misconfiguration"
    elif category == "session_management":
        return "WSTG-SESS-02", "A07:2021-Identification and Authentication Failures"
    return "WSTG-GEN-01", "A05:2021-Security Misconfiguration"


def parse_zap_alerts(alerts_input: Union[str, List[Dict[str, Any]], Dict[str, Any]]) -> List[CandidateFinding]:
    """
    Pure parser converting ZAP alert JSON outputs into normalized CandidateFinding objects.
    Groups alerts by name and risk while retaining a bounded set of URL-level evidence.
    """
    alerts_data: List[Dict[str, Any]] = []

    if isinstance(alerts_input, str):
        try:
            parsed = json.loads(alerts_input)
            if isinstance(parsed, dict) and "alerts" in parsed:
                alerts_data = parsed["alerts"]
            elif isinstance(parsed, list):
                alerts_data = parsed
            elif isinstance(parsed, dict):
                alerts_data = [parsed]
        except Exception:
            return []
    elif isinstance(alerts_input, dict):
        alerts_data = alerts_input.get("alerts", [alerts_input])
    elif isinstance(alerts_input, list):
        alerts_data = alerts_input

    grouped: Dict[tuple[str, str], Dict[str, Any]] = {}

    for alert in alerts_data:
        name = alert.get("name") or alert.get("alert") or "ZAP Vulnerability Alert"
        plugin_id = str(alert.get("pluginId", ""))
        category = map_zap_category(name, plugin_id)
        wstg_id, owasp_top10 = map_zap_wstg_and_owasp(category)

        raw_risk = str(alert.get("risk", "low")).strip().lower()
        severity = ZAP_RISK_MAP.get(raw_risk, FindingSeverity.LOW)
        if severity == FindingSeverity.INFO:
            continue

        url = alert.get("url") or "http://target.local"
        risk_key = severity.value if raw_risk in ZAP_RISK_MAP else raw_risk
        group_key = (" ".join(name.split()).casefold(), risk_key)
        group = grouped.get(group_key)
        if group is None:
            cwe_raw = str(alert.get("cweid", "")).strip()
            cwe = f"CWE-{cwe_raw}" if cwe_raw and cwe_raw != "0" else None
            group = {
                "name": name,
                "category": category,
                "wstg_id": wstg_id,
                "owasp_top10": owasp_top10,
                "severity": severity,
                "cwe": cwe,
                "description": alert.get("description", ""),
                "solution": alert.get("solution")
                or "Consult OWASP remediation guidance for this vulnerability.",
                "urls": [],
                "url_set": set(),
                "evidence": [],
                "alert_count": 0,
            }
            grouped[group_key] = group

        param = alert.get("param")
        reference = alert.get("reference")
        if reference and reference not in group["solution"]:
            group["solution"] = f"{group['solution']}\nReference: {reference}"

        group["alert_count"] += 1
        if url not in group["url_set"]:
            group["url_set"].add(url)
            group["urls"].append(url)
            if len(group["evidence"]) < MAX_EVIDENCE_URLS:
                evidence = (
                    f"URL: {url}\n"
                    f"Plugin ID: {alert.get('pluginId', 'N/A')}\n"
                    f"Parameter: {param or 'N/A'}\n"
                    f"Evidence Snippet: {alert.get('evidence') or 'N/A'}\n"
                    f"CWE: {group['cwe'] or 'N/A'} | WASC: {alert.get('wascid', 'N/A')}\n"
                    f"Other Info: {alert.get('other', 'N/A')}"
                )
                group["evidence"].append(evidence)

    candidates: List[CandidateFinding] = []
    for group in grouped.values():
        urls = group["urls"]
        evidence_lines = [
            f"ZAP Alert: {group['name']} (Risk: {group['severity'].value})",
            f"Affected URL count: {len(urls)}",
            f"Alert count: {group['alert_count']}",
            f"Affected URLs (first {MAX_EVIDENCE_URLS}):",
        ]
        evidence_lines.extend(f"- {url}" for url in urls[:MAX_EVIDENCE_URLS])
        evidence_lines.append(
            f"Evidence samples (first {MAX_EVIDENCE_URLS} affected URLs):"
        )
        for sample in group["evidence"]:
            evidence_lines.extend(f"  {line}" for line in sample.splitlines())
        evidence_content = "\n".join(evidence_lines)
        description = group["description"]

        candidates.append(
            CandidateFinding(
                title=f"[ZAP] {group['name']}",
                category=group["category"],
                description=description,
                severity=group["severity"],
                affected_url=urls[0] if urls else "http://target.local",
                wstg_id=group["wstg_id"],
                owasp_top10=group["owasp_top10"],
                cwe=group["cwe"],
                remediation=group["solution"],
                evidence_label=f"ZAP Alert: {group['name']}",
                evidence_content=evidence_content,
                affected_urls=urls[:MAX_EVIDENCE_URLS],
            )
        )

    return candidates


class ZapParser:
    """OWASP ZAP alerts parser wrapper."""

    def parse_alerts(self, alerts_input: Any) -> List[CandidateFinding]:
        return parse_zap_alerts(alerts_input)
