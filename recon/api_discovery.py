"""API endpoint discovery - extracts API routes from JavaScript sources and probes common paths."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


@dataclass
class ApiEndpoint:
    """A single discovered API endpoint."""
    url: str
    method: str = "UNKNOWN"
    source: str = ""  # where the endpoint was found (script URL, probe, etc.)


@dataclass
class ApiMap:
    """Aggregated API discovery results."""
    discovered_endpoints: List[ApiEndpoint] = field(default_factory=list)
    common_paths_checked: Dict[str, bool] = field(default_factory=dict)


# Regex patterns to extract API-like URLs from JavaScript source code.
_API_PATH_PATTERNS: List[re.Pattern[str]] = [
    # Quoted strings that look like API paths: "/api/...", '/v1/...'
    re.compile(r"""["'`](\/(?:api|v\d+|graphql|rest|auth|admin|users?|login|register|logout|search|upload|download)\b[^"'`\s]{0,200})["'`]""", re.I),
    # Generic slash-delimited paths starting with /api
    re.compile(r"""["'`](\/api\/[a-zA-Z0-9_/:.{}\[\]\-]+)["'`]"""),
]

# Patterns that capture the HTTP method alongside a URL.
_METHOD_URL_PATTERNS: List[tuple[re.Pattern[str], int, int]] = [
    # fetch("/url", { method: "POST" })  -  url in group 1, method in group 2
    (re.compile(
        r"""fetch\(\s*["'`]([^"'`]+)["'`]\s*,\s*\{[^}]*?method\s*:\s*["'`](\w+)["'`]""",
        re.I | re.S,
    ), 1, 2),
    # axios.post("/url") / axios.get("/url") etc.
    (re.compile(
        r"""axios\.(get|post|put|patch|delete|head|options)\(\s*["'`]([^"'`]+)["'`]""",
        re.I,
    ), 2, 1),
    # $.ajax({ url: "/url", method/type: "POST" })
    (re.compile(
        r"""\$\.ajax\(\s*\{[^}]*?url\s*:\s*["'`]([^"'`]+)["'`][^}]*?(?:method|type)\s*:\s*["'`](\w+)["'`]""",
        re.I | re.S,
    ), 1, 2),
    # XMLHttpRequest .open("GET", "/url")
    (re.compile(
        r"""\.open\(\s*["'`](\w+)["'`]\s*,\s*["'`]([^"'`]+)["'`]""",
        re.I,
    ), 2, 1),
    # fetch("/url") without explicit method (implies GET)
    (re.compile(
        r"""fetch\(\s*["'`]([^"'`]+)["'`]\s*\)""",
        re.I,
    ), 1, 0),
]

# Well-known API / documentation paths to probe.
_COMMON_API_PATHS: List[tuple[str, str]] = [
    ("/api", "GET"),
    ("/api/v1", "GET"),
    ("/api/v2", "GET"),
    ("/graphql", "GET"),
    ("/api/health", "GET"),
    ("/api/status", "GET"),
    ("/api/docs", "GET"),
    ("/api/schema", "GET"),
    ("/swagger.json", "GET"),
    ("/swagger/v1/swagger.json", "GET"),
    ("/openapi.json", "GET"),
    ("/api-docs", "GET"),
    ("/api/config", "GET"),
    ("/api/version", "GET"),
    ("/api/info", "GET"),
    ("/api/me", "GET"),
    ("/api/user", "GET"),
    ("/api/users", "GET"),
    ("/api/auth", "GET"),
    ("/api/login", "POST"),
    ("/api/register", "POST"),
    ("/api/graphql", "GET"),
    ("/.env", "GET"),
    ("/wp-json/wp/v2", "GET"),
]


class ApiDiscovery:
    """Discovers API endpoints by analysing JavaScript sources and probing common paths."""

    def discover(
        self,
        http_client: Any,
        base_url: str,
        scripts: Optional[List[str]] = None,
    ) -> ApiMap:
        """Discover API endpoints for *base_url*.

        Args:
            http_client: HTTP client (from core.http_client) with allowlist
                and rate-limiting enforcement.
            base_url: Root URL of the target application.
            scripts: List of JavaScript file URLs found by the crawler.

        Returns:
            An :class:`ApiMap` with all findings.
        """
        api_map = ApiMap()
        seen_endpoints: set[tuple[str, str]] = set()

        # 1. Analyse each JavaScript file.
        for script_url in (scripts or []):
            self._analyze_script(http_client, base_url, script_url, api_map, seen_endpoints)

        # 2. Probe common API paths.
        self._probe_common_paths(http_client, base_url, api_map, seen_endpoints)

        logger.info(
            "API discovery complete: %d endpoints found, %d common paths checked",
            len(api_map.discovered_endpoints),
            len(api_map.common_paths_checked),
        )
        return api_map

    # ------------------------------------------------------------------
    # Script analysis
    # ------------------------------------------------------------------

    def _analyze_script(
        self,
        http_client: Any,
        base_url: str,
        script_url: str,
        api_map: ApiMap,
        seen: set[tuple[str, str]],
    ) -> None:
        try:
            response = http_client.get(script_url)
        except Exception as exc:
            logger.warning("Failed to fetch script %s: %s", script_url, exc)
            return

        if response.status_code != 200:
            return

        js_text = response.text

        # --- Method-aware patterns ---
        for pattern, url_group, method_group in _METHOD_URL_PATTERNS:
            for match in pattern.finditer(js_text):
                url_raw = match.group(url_group)
                method = match.group(method_group).upper() if method_group != 0 else "GET"
                resolved = self._resolve_url(base_url, url_raw)
                key = (resolved, method)
                if key not in seen:
                    seen.add(key)
                    api_map.discovered_endpoints.append(
                        ApiEndpoint(url=resolved, method=method, source=script_url)
                    )

        # --- Generic API path patterns ---
        for pattern in _API_PATH_PATTERNS:
            for match in pattern.finditer(js_text):
                url_raw = match.group(1)
                resolved = self._resolve_url(base_url, url_raw)
                key = (resolved, "UNKNOWN")
                if key not in seen:
                    # Check if we already have this URL with a known method.
                    if not any(ep.url == resolved for ep in api_map.discovered_endpoints):
                        seen.add(key)
                        api_map.discovered_endpoints.append(
                            ApiEndpoint(url=resolved, method="UNKNOWN", source=script_url)
                        )

    # ------------------------------------------------------------------
    # Probing common paths
    # ------------------------------------------------------------------

    def _probe_common_paths(
        self,
        http_client: Any,
        base_url: str,
        api_map: ApiMap,
        seen: set[tuple[str, str]],
    ) -> None:
        for path, method in _COMMON_API_PATHS:
            url = urljoin(base_url, path)
            try:
                if method == "GET":
                    resp = http_client.get(url)
                else:
                    # For POST probes we send an empty body just to check availability.
                    if hasattr(http_client, "post"):
                        resp = http_client.post(url, data="")
                    else:
                        resp = http_client.get(url)
                exists = resp.status_code not in (404, 405, 502, 503)
            except Exception:
                exists = False

            api_map.common_paths_checked[path] = exists

            if exists:
                key = (url, method)
                if key not in seen:
                    seen.add(key)
                    api_map.discovered_endpoints.append(
                        ApiEndpoint(url=url, method=method, source="common_path_probe")
                    )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_url(base_url: str, raw: str) -> str:
        """Resolve a possibly-relative URL against the base URL.

        Handles template parameters like ``/api/users/:id`` or
        ``/api/users/{id}`` by keeping them as-is.
        """
        if raw.startswith(("http://", "https://")):
            return raw
        return urljoin(base_url, raw)
