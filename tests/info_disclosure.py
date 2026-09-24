"""Information disclosure tests.

Checks for leaked sensitive data in API responses, error pages,
exposed files, HTTP headers, source maps, robots.txt, and CORS
misconfiguration.
"""

from __future__ import annotations

import logging
import re
from typing import List
from urllib.parse import urljoin

from tests import BaseTest

logger = logging.getLogger(__name__)

# Patterns that indicate sensitive data leakage in response bodies.
_SENSITIVE_PATTERNS = {
    "password_field": re.compile(
        r'"password"\s*:\s*"[^"]+"', re.IGNORECASE
    ),
    "token_field": re.compile(
        r'"(access_token|refresh_token|api_key|secret_key|jwt)"\s*:\s*"[^"]+"',
        re.IGNORECASE,
    ),
    "internal_ip": re.compile(
        r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
        r"|192\.168\.\d{1,3}\.\d{1,3})\b"
    ),
    "stack_trace": re.compile(
        r"(Traceback \(most recent call last\)"
        r"|at\s+[\w$.]+\([\w]+\.java:\d+\)"
        r"|in\s+[\w/\\]+\.py,?\s+line\s+\d+"
        r"|\.js:\d+:\d+)",
        re.IGNORECASE,
    ),
}

# Well-known files that should not be publicly accessible.
_SENSITIVE_FILES = [
    "/.env",
    "/config.json",
    "/.git/HEAD",
    "/package.json",
    "/composer.json",
    "/.DS_Store",
    "/wp-config.php",
    "/server-status",
    "/phpinfo.php",
]

# HTTP headers commonly leaking version information.
_VERSION_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Runtime",
    "X-Generator",
]

# Origins used to probe CORS policy.
_CORS_ORIGINS = [
    "https://evil.com",
    "null",
    "https://attacker.example.org",
]


class InfoDisclosureTest(BaseTest):
    """Test suite for information disclosure vulnerabilities."""

    MODULE_NAME = "info_disclosure"

    def run(self) -> List:
        logger.info("Starting information disclosure tests")

        self._check_api_response_leaks()
        self._check_error_responses()
        self._check_sensitive_files()
        self._check_version_headers()
        self._check_source_maps()
        self._check_robots_sitemap()
        self._check_cors()

        logger.info(
            "Information disclosure tests complete: %d results recorded",
            len(self.results),
        )
        return self.results

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _base_url(self) -> str:
        return self.config.get("target", {}).get("base_url", "")

    def _check_api_response_leaks(self) -> None:
        """Inspect discovered API endpoints for sensitive data in responses."""
        logger.info("Checking API responses for excessive data leakage")
        endpoints = self.recon.get("api_endpoints", [])
        if not endpoints:
            logger.info("No API endpoints discovered - skipping API leak check")
            self.add_result(
                test_name="API Response Data Leakage",
                test_module=self.MODULE_NAME,
                status="not_tested",
                severity="info",
                description="No API endpoints available from recon to test.",
                target_url=self._base_url(),
                expected_behavior="API responses should not contain passwords, tokens, or internal IPs.",
                actual_behavior="No endpoints to test.",
                reproduction_steps=["Run recon phase first to discover API endpoints."],
                evidence="",
                remediation="Ensure API responses are stripped of sensitive fields.",
                retest_description="Re-run after recon discovers API endpoints.",
            )
            return

        for ep in endpoints[:10]:  # cap to avoid excessive requests
            ep_url = ep["url"] if isinstance(ep, dict) else ep
            url = ep_url if ep_url.startswith("http") else urljoin(self._base_url(), ep_url)
            try:
                resp = self.http.get(url)
                body = resp.text
                found_patterns = []
                for name, pattern in _SENSITIVE_PATTERNS.items():
                    match = pattern.search(body)
                    if match:
                        found_patterns.append(f"{name}: {match.group()[:120]}")

                if found_patterns:
                    self.add_result(
                        test_name="API Response Data Leakage",
                        test_module=self.MODULE_NAME,
                        status="suspected_unverified",
                        severity="high",
                        description=f"Sensitive data patterns found in response from {url}.",
                        target_url=url,
                        expected_behavior="Response should not contain passwords, tokens, or internal IPs.",
                        actual_behavior=f"Found: {'; '.join(found_patterns)}",
                        reproduction_steps=[f"GET {url}", "Inspect JSON body for sensitive fields."],
                        evidence="\n".join(found_patterns),
                        remediation="Strip sensitive fields from API responses. Use allow-list serialization.",
                        retest_description="Repeat GET request and verify sensitive patterns are absent.",
                    )
                else:
                    self.add_result(
                        test_name="API Response Data Leakage",
                        test_module=self.MODULE_NAME,
                        status="blocked",
                        severity="info",
                        description=f"No sensitive data patterns detected in {url}.",
                        target_url=url,
                        expected_behavior="No sensitive data in response body.",
                        actual_behavior="No sensitive patterns matched.",
                        reproduction_steps=[f"GET {url}"],
                        evidence="",
                        remediation="N/A",
                        retest_description="Re-check after application changes.",
                    )
            except Exception as exc:
                logger.warning("Error checking API leaks at %s: %s", url, exc)
                self.add_result(
                    test_name="API Response Data Leakage",
                    test_module=self.MODULE_NAME,
                    status="not_tested",
                    severity="info",
                    description=f"Could not reach {url}: {exc}",
                    target_url=url,
                    expected_behavior="Endpoint reachable for testing.",
                    actual_behavior=f"Request failed: {exc}",
                    reproduction_steps=[f"GET {url}"],
                    evidence=str(exc),
                    remediation="Verify endpoint availability.",
                    retest_description="Retry when endpoint is accessible.",
                )

    def _check_error_responses(self) -> None:
        """Trigger error pages and inspect for stack traces / DB info."""
        logger.info("Checking error responses for information leakage")
        base = self._base_url()
        error_triggers = [
            (f"{base}/nonexistent_path_404_test", "404 trigger"),
            (f"{base}/api/v1/../../etc/passwd", "path traversal trigger"),
            (f"{base}/api/v1/?id='OR+1=1--", "SQL error trigger"),
        ]

        for url, label in error_triggers:
            try:
                resp = self.http.get(url)
                body = resp.text
                leaks = []
                if _SENSITIVE_PATTERNS["stack_trace"].search(body):
                    leaks.append("stack_trace")
                # Check for DB-related keywords in errors
                db_keywords = re.search(
                    r"(mysql|postgresql|sqlite|oracle|sql\s+syntax|ORA-\d+|SQLSTATE)",
                    body,
                    re.IGNORECASE,
                )
                if db_keywords:
                    leaks.append(f"db_info ({db_keywords.group()})")
                # File paths
                path_leak = re.search(
                    r"(/var/www/|/home/\w+|C:\\\\|/usr/|/opt/|/srv/)",
                    body,
                    re.IGNORECASE,
                )
                if path_leak:
                    leaks.append(f"file_path ({path_leak.group()[:60]})")

                status = "suspected_unverified" if leaks else "blocked"
                severity = "medium" if leaks else "info"
                self.add_result(
                    test_name="Error Response Information Leakage",
                    test_module=self.MODULE_NAME,
                    status=status,
                    severity=severity,
                    description=f"{label}: {'leaks detected' if leaks else 'no leaks detected'} (HTTP {resp.status_code}).",
                    target_url=url,
                    expected_behavior="Error pages should be generic with no internal details.",
                    actual_behavior=f"{'Leaked: ' + ', '.join(leaks) if leaks else 'Generic error page returned.'}",
                    reproduction_steps=[f"GET {url}", "Inspect response body for internal details."],
                    evidence="; ".join(leaks) if leaks else "",
                    remediation="Configure custom error pages. Disable debug mode in production.",
                    retest_description="Repeat request and verify error page is generic.",
                )
            except Exception as exc:
                logger.warning("Error triggering %s: %s", label, exc)

    def _check_sensitive_files(self) -> None:
        """Attempt to access well-known sensitive files."""
        logger.info("Checking for publicly accessible sensitive files")
        base = self._base_url()

        for path in _SENSITIVE_FILES:
            url = f"{base}{path}"
            try:
                resp = self.http.get(url)
                accessible = resp.status_code == 200 and len(resp.text) > 0
                status = "suspected_unverified" if accessible else "blocked"
                severity = "high" if accessible else "info"
                self.add_result(
                    test_name="Sensitive File Exposure",
                    test_module=self.MODULE_NAME,
                    status=status,
                    severity=severity,
                    description=f"{path} {'is accessible' if accessible else 'not accessible'} (HTTP {resp.status_code}).",
                    target_url=url,
                    expected_behavior=f"{path} should return 403 or 404.",
                    actual_behavior=f"HTTP {resp.status_code}, body length {len(resp.text)}.",
                    reproduction_steps=[f"GET {url}"],
                    evidence=resp.text[:300] if accessible else "",
                    remediation=f"Block access to {path} via web server configuration.",
                    retest_description=f"GET {url} and confirm non-200 response.",
                )
            except Exception as exc:
                logger.warning("Error checking %s: %s", path, exc)

    def _check_version_headers(self) -> None:
        """Inspect HTTP response headers for version disclosure."""
        logger.info("Checking HTTP headers for version disclosure")
        base = self._base_url()
        try:
            resp = self.http.get(base)
            disclosed = []
            for hdr in _VERSION_HEADERS:
                value = resp.headers.get(hdr)
                if value:
                    disclosed.append(f"{hdr}: {value}")

            status = "suspected_unverified" if disclosed else "blocked"
            severity = "low" if disclosed else "info"
            self.add_result(
                test_name="HTTP Header Version Disclosure",
                test_module=self.MODULE_NAME,
                status=status,
                severity=severity,
                description=f"{'Version info disclosed in headers' if disclosed else 'No version headers found'}.",
                target_url=base,
                expected_behavior="Server should not disclose software versions in headers.",
                actual_behavior="; ".join(disclosed) if disclosed else "No version headers present.",
                reproduction_steps=[f"GET {base}", "Inspect response headers."],
                evidence="\n".join(disclosed),
                remediation="Remove or suppress Server, X-Powered-By, and similar headers.",
                retest_description="GET base URL and check response headers.",
            )
        except Exception as exc:
            logger.warning("Error checking headers: %s", exc)

    def _check_source_maps(self) -> None:
        """Look for JavaScript source maps (.map files)."""
        logger.info("Checking for exposed source maps")
        scripts = self.recon.get("scripts_found", [])
        if not scripts:
            return

        for script_url in scripts[:10]:
            map_url = f"{script_url}.map"
            try:
                resp = self.http.get(map_url)
                accessible = (
                    resp.status_code == 200
                    and ("mappings" in resp.text or "sources" in resp.text)
                )
                if accessible:
                    self.add_result(
                        test_name="Source Map Exposure",
                        test_module=self.MODULE_NAME,
                        status="suspected_unverified",
                        severity="medium",
                        description=f"Source map accessible at {map_url}.",
                        target_url=map_url,
                        expected_behavior="Source maps should not be publicly accessible in production.",
                        actual_behavior=f"HTTP 200, body contains source map data ({len(resp.text)} bytes).",
                        reproduction_steps=[f"GET {map_url}"],
                        evidence=resp.text[:300],
                        remediation="Remove .map files from production or restrict access.",
                        retest_description=f"GET {map_url} and verify non-200 response.",
                    )
            except Exception as exc:
                logger.debug("Error checking source map %s: %s", map_url, exc)

    def _check_robots_sitemap(self) -> None:
        """Inspect robots.txt and sitemap.xml for hidden paths."""
        logger.info("Checking robots.txt and sitemap.xml")
        base = self._base_url()

        for filename in ["robots.txt", "sitemap.xml"]:
            url = f"{base}/{filename}"
            try:
                resp = self.http.get(url)
                if resp.status_code != 200 or not resp.text.strip():
                    continue

                hidden_paths = []
                if filename == "robots.txt":
                    for line in resp.text.splitlines():
                        line = line.strip()
                        if line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path and path != "/":
                                hidden_paths.append(path)
                else:
                    # sitemap: extract <loc> entries
                    locs = re.findall(r"<loc>(.*?)</loc>", resp.text, re.IGNORECASE)
                    hidden_paths = locs[:20]

                if hidden_paths:
                    self.add_result(
                        test_name="Hidden Paths in robots.txt/sitemap",
                        test_module=self.MODULE_NAME,
                        status="suspected_unverified",
                        severity="low",
                        description=f"{filename} reveals {len(hidden_paths)} path(s) that may be sensitive.",
                        target_url=url,
                        expected_behavior="robots.txt/sitemap should not reveal admin or sensitive paths.",
                        actual_behavior=f"Paths found: {', '.join(hidden_paths[:10])}",
                        reproduction_steps=[f"GET {url}", "Review listed paths."],
                        evidence="\n".join(hidden_paths[:15]),
                        remediation="Review listed paths for sensitive endpoints. Restrict access where needed.",
                        retest_description=f"GET {url} and review paths.",
                    )
            except Exception as exc:
                logger.warning("Error fetching %s: %s", filename, exc)

    def _check_cors(self) -> None:
        """Test CORS policy with various Origin headers."""
        logger.info("Checking CORS configuration")
        base = self._base_url()

        for origin in _CORS_ORIGINS:
            try:
                resp = self.http.get(
                    base, headers={"Origin": origin}
                )
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                misconfigured = False
                details = []
                if acao == "*":
                    misconfigured = True
                    details.append("ACAO is wildcard (*)")
                if acao == origin:
                    misconfigured = True
                    details.append(f"ACAO reflects arbitrary origin ({origin})")
                if acac.lower() == "true" and acao != "":
                    misconfigured = True
                    details.append("Credentials allowed with permissive ACAO")

                if misconfigured:
                    self.add_result(
                        test_name="CORS Misconfiguration",
                        test_module=self.MODULE_NAME,
                        status="suspected_unverified",
                        severity="high",
                        description=f"CORS misconfiguration detected with Origin: {origin}.",
                        target_url=base,
                        expected_behavior="Server should not reflect arbitrary origins or use wildcard with credentials.",
                        actual_behavior="; ".join(details),
                        reproduction_steps=[
                            f"GET {base} with header Origin: {origin}",
                            "Inspect Access-Control-Allow-Origin and Access-Control-Allow-Credentials.",
                        ],
                        evidence=f"ACAO={acao}, ACAC={acac}",
                        remediation="Whitelist specific trusted origins. Never reflect arbitrary Origin with credentials.",
                        retest_description=f"Send request with Origin: {origin} and check CORS headers.",
                    )
                else:
                    self.add_result(
                        test_name="CORS Misconfiguration",
                        test_module=self.MODULE_NAME,
                        status="blocked",
                        severity="info",
                        description=f"CORS properly configured for Origin: {origin}.",
                        target_url=base,
                        expected_behavior="Arbitrary origins should be rejected.",
                        actual_behavior=f"ACAO={acao or '(absent)'}, ACAC={acac or '(absent)'}.",
                        reproduction_steps=[f"GET {base} with header Origin: {origin}"],
                        evidence="",
                        remediation="N/A",
                        retest_description="Re-check after configuration changes.",
                    )
            except Exception as exc:
                logger.warning("Error testing CORS with origin %s: %s", origin, exc)
