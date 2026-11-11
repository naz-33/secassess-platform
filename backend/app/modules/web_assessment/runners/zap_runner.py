import json
import re
import time
import urllib.parse
import uuid
from typing import Dict, Any, List, Optional, Tuple
import httpx
from sqlalchemy.orm import Session
from app.core.config import settings
from app.modules.targets import ScopeManager
from app.modules.web_assessment.parsers.zap_parser import parse_zap_alerts
from app.modules.web_assessment.types import CandidateFinding

MAX_SPIDER_DEPTH = 5
MAX_SPIDER_URLS = 500


def has_repeated_path_segment(url: str) -> bool:
    """Return whether a decoded URL path contains any segment more than once."""
    try:
        path = urllib.parse.urlsplit(url).path
    except ValueError:
        return True
    segments = [
        urllib.parse.unquote(segment)
        for segment in path.split("/")
        if segment
    ]
    return len(segments) != len(set(segments))


def filter_spidered_urls(
    urls: List[str],
    max_urls: Optional[int] = None,
) -> List[str]:
    """Drop recursive and duplicate endpoints, preserving order and enforcing a cap."""
    configured_limit = settings.ZAP_SPIDER_MAX_URLS if max_urls is None else max_urls
    limit = max(0, min(configured_limit, MAX_SPIDER_URLS))
    if limit == 0:
        return []
    filtered: List[str] = []
    seen = set()
    for url in urls:
        if has_repeated_path_segment(url):
            continue
        try:
            parsed = urllib.parse.urlsplit(url)
        except ValueError:
            continue
        key = urllib.parse.urlunsplit(
            (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path, parsed.query, "")
        )
        if key in seen:
            continue
        seen.add(key)
        filtered.append(url)
        if len(filtered) >= limit:
            break
    return filtered


class ZapRunner:
    """
    OWASP ZAP integration runner interacting with the ZAP daemon REST API.
    Enforces scope restrictions, non-destructive defaults, and graceful error handling.
    """

    def __init__(
        self,
        db: Session,
        target_id: uuid.UUID,
        zap_api_url: Optional[str] = None,
        zap_api_key: Optional[str] = None,
        timeout: float = 10.0,
    ):
        self.db = db
        self.target_id = target_id
        self.scope_manager = ScopeManager(db)
        self.zap_url = (zap_api_url or settings.ZAP_API_URL).rstrip("/")
        self.zap_key = zap_api_key if zap_api_key is not None else settings.ZAP_API_KEY
        self.timeout = timeout

    def _request(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make an authenticated HTTP GET request to ZAP REST API."""
        query_params = dict(params or {})
        if self.zap_key:
            query_params["apikey"] = self.zap_key

        url = f"{self.zap_url}/{endpoint.lstrip('/')}"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.get(url, params=query_params)
                res.raise_for_status()
                return res.json()
        except (httpx.ConnectError, httpx.TimeoutException) as ce:
            raise ConnectionError(
                f"OWASP ZAP daemon at '{self.zap_url}' is unreachable. "
                "Likely causes: ZAP is stopped or still starting, ZAP_API_URL uses a "
                "host-local address instead of the Docker service name, the containers "
                "are not on the same network, or ZAP_API_KEY does not match."
            ) from ce
        except Exception as exc:
            message = str(exc)
            if self.zap_key:
                message = message.replace(self.zap_key, "[REDACTED]")
            raise RuntimeError(
                f"ZAP API request to '{self.zap_url}/{endpoint.lstrip('/')}' failed. "
                f"Check that ZAP is running and ZAP_API_KEY matches: {message}"
            ) from exc

    def check_reachability(self) -> str:
        """Verify ZAP readiness, retrying briefly while its daemon starts."""
        for attempt in range(3):
            try:
                data = self._request("JSON/core/view/version/")
                return data.get("version", "unknown")
            except ConnectionError:
                if attempt == 2:
                    raise
                time.sleep(1)
        raise RuntimeError("OWASP ZAP reachability check ended unexpectedly.")

    def setup_context(self, context_name: str, target_url: str, out_of_scope_assets: List[str]) -> str:
        """Create or configure a ZAP context strictly bounded by authorized target scope."""
        # 1. Create new context
        ctx_data = self._request("JSON/context/action/newContext/", {"contextName": context_name})
        context_id = ctx_data.get("contextId", "1")

        # 2. Include in-scope target regex
        escaped_target = re.escape(target_url.rstrip("/"))
        include_regex = f"{escaped_target}.*"
        self._request(
            "JSON/context/action/includeInContext/",
            {"contextName": context_name, "regex": include_regex},
        )

        # 3. Exclude out-of-scope/blacklisted assets
        for oos in out_of_scope_assets:
            if oos.strip():
                exclude_regex = f"{re.escape(oos.strip())}.*"
                self._request(
                    "JSON/context/action/excludeFromContext/",
                    {"contextName": context_name, "regex": exclude_regex},
                )

        repeated_segment_regex = (
            f"^{re.escape(target_url.rstrip('/'))}"
            r"(?:/[^/?#]+)*/([^/?#]+)(?:/[^/?#]+)*/\1(?:/|[?#]|$)"
        )
        self._request(
            "JSON/context/action/excludeFromContext/",
            {"contextName": context_name, "regex": repeated_segment_regex},
        )

        return context_id

    def run_spider(
        self,
        target_url: str,
        context_name: Optional[str] = None,
        max_depth: int = 2,
        max_duration_mins: int = 2,
    ) -> List[str]:
        """Trigger ZAP spider and poll until completion or timeout."""
        effective_depth = max(0, min(int(max_depth), MAX_SPIDER_DEPTH))
        max_urls = max(1, min(settings.ZAP_SPIDER_MAX_URLS, MAX_SPIDER_URLS))
        params: Dict[str, Any] = {
            "url": target_url,
            "maxDepth": effective_depth,
            "maxChildren": max_urls,
            "recurse": "true",
        }
        if context_name:
            params["contextName"] = context_name

        data = self._request("JSON/spider/action/scan/", params)
        scan_id = data.get("scan")
        if not scan_id:
            raise RuntimeError("ZAP did not return a scan ID for the spider.")

        # Poll spider status
        deadline = time.time() + (max_duration_mins * 60)
        completed = False
        stop_requested = False
        while time.time() < deadline:
            status_data = self._request("JSON/spider/view/status/", {"scanId": scan_id})
            progress = int(status_data.get("status", "0"))
            if progress >= 100:
                completed = True
                break
            if not stop_requested:
                partial_results = self._request(
                    "JSON/spider/view/results/",
                    {"scanId": scan_id},
                ).get("results", [])
                if len(set(partial_results)) >= max_urls:
                    self._request("JSON/spider/action/stop/", {"scanId": scan_id})
                    stop_requested = True
            time.sleep(1.0)
        if not completed:
            raise TimeoutError(f"ZAP spider scan {scan_id} did not complete before its time limit.")

        # Retrieve spidered URLs
        results_data = self._request("JSON/spider/view/results/", {"scanId": scan_id})
        raw_urls = results_data.get("results", [])

        # Filter spidered URLs strictly through ScopeManager
        in_scope_urls: List[str] = []
        for u in raw_urls:
            if has_repeated_path_segment(u):
                continue
            is_valid, _ = self.scope_manager.check_scope(self.target_id, u)
            if is_valid:
                in_scope_urls.append(u)

        return filter_spidered_urls(in_scope_urls, max_urls=max_urls)

    def wait_for_passive_scan(self, max_wait_seconds: int = 30) -> None:
        """Poll until ZAP's passive scanner queue is drained."""
        deadline = time.time() + max_wait_seconds
        while time.time() < deadline:
            pscan_data = self._request("JSON/pscan/view/recordsToScan/")
            remaining = int(pscan_data.get("recordsToScan", "0"))
            if remaining == 0:
                return
            time.sleep(1.0)
        raise TimeoutError("ZAP passive scanner queue did not drain before its time limit.")

    def trigger_active_scan(
        self,
        target_url: str,
        context_id: Optional[str] = None,
        max_duration_mins: int = 2,
    ) -> None:
        """
        Run ZAP active scan.
        Safety gate: Requires settings.ZAP_ALLOW_ACTIVE_SCAN=True.
        """
        if not settings.ZAP_ALLOW_ACTIVE_SCAN:
            raise ValueError(
                "Active scanning in ZAP is disabled by default and rejected by safety policy. "
                "Set ZAP_ALLOW_ACTIVE_SCAN=True in settings to permit non-destructive active scanning."
            )

        params: Dict[str, Any] = {"url": target_url, "recurse": "true", "inScopeOnly": "true"}
        if context_id:
            params["contextId"] = context_id

        data = self._request("JSON/ascan/action/scan/", params)
        ascan_id = data.get("scan")
        if not ascan_id:
            raise RuntimeError("ZAP did not return a scan ID for the active scan.")

        deadline = time.time() + (max_duration_mins * 60)
        completed = False
        while time.time() < deadline:
            st = self._request("JSON/ascan/view/status/", {"scanId": ascan_id})
            if int(st.get("status", "0")) >= 100:
                completed = True
                break
            time.sleep(1.0)
        if not completed:
            raise TimeoutError(f"ZAP active scan {ascan_id} did not complete before its time limit.")

    def fetch_alerts(self, target_url: str) -> Tuple[List[Dict[str, Any]], str]:
        """Fetch all alerts recorded by ZAP for the target URL and return (alerts_list, raw_json_str)."""
        data = self._request("JSON/core/view/alerts/", {"baseurl": target_url})
        alerts = data.get("alerts", [])
        raw_json = json.dumps(data, indent=2)
        return alerts, raw_json

    def execute_zap_assessment(
        self,
        target_url: str,
        out_of_scope_assets: List[str],
        run_active_scan: bool = False,
        spider_depth: Optional[int] = None,
        spider_duration: Optional[int] = None,
    ) -> Tuple[List[CandidateFinding], List[str], str]:
        """
        Complete ZAP workflow:
        1. Reachability check
        2. Scope validation & Context setup
        3. Spider
        4. Passive scan drain
        5. Active scan (if explicitly enabled)
        6. Alert fetching & parsing
        Returns:
            (candidate_findings, spidered_urls, raw_alerts_json)
        """
        # 1. Reachability
        self.check_reachability()

        # 2. Scope validation
        is_in_scope, reason = self.scope_manager.check_scope(self.target_id, target_url)
        if not is_in_scope:
            raise ValueError(f"Target URL '{target_url}' is out of scope for ZAP: {reason}")

        # 3. Context setup
        ctx_name = f"context_{uuid.uuid4().hex[:8]}"
        ctx_id = self.setup_context(ctx_name, target_url, out_of_scope_assets)

        # 4. Spider
        depth = spider_depth if spider_depth is not None else settings.ZAP_SPIDER_MAX_DEPTH
        duration = spider_duration if spider_duration is not None else settings.ZAP_SPIDER_MAX_DURATION_MINS
        spidered_urls = self.run_spider(
            target_url=target_url,
            context_name=ctx_name,
            max_depth=depth,
            max_duration_mins=duration,
        )

        # 5. Passive scan drain
        self.wait_for_passive_scan(max_wait_seconds=15)

        # 6. Active scan (if requested and enabled)
        if run_active_scan:
            self.trigger_active_scan(target_url=target_url, context_id=ctx_id, max_duration_mins=duration)

        # 7. Fetch alerts
        alerts_list, raw_json = self.fetch_alerts(target_url=target_url)
        candidates = parse_zap_alerts(alerts_list)

        return candidates, spidered_urls, raw_json
