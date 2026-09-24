"""Input validation tests.

Covers XSS (reflected and stored), SQL injection, NoSQL injection,
CRLF / header injection, and malicious file upload.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from tests import BaseTest

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------
# Payload banks
# ---------------------------------------------------------------

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<img onerror=alert(1) src=x>',
    '<svg onload=alert(1)>',
    'javascript:alert(1)',
    '" onfocus=alert(1) autofocus="',
    "' onfocus=alert(1) autofocus='",
    '<body onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "';alert(1)//",
]

SQLI_PAYLOADS = [
    "' OR 1=1--",
    "'; DROP TABLE users--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' OR '1'='1",
    "admin'--",
    "1; SELECT * FROM users--",
    "' OR ''='",
]

NOSQL_PAYLOADS: List[Any] = [
    {"$gt": ""},
    {"$ne": None},
    {"$regex": ".*"},
    {"$exists": True},
]

CRLF_PAYLOADS = [
    "value\r\nInjected-Header: true",
    "value%0d%0aInjected-Header:%20true",
    "value\r\n\r\n<html>injected</html>",
]

# Malicious filenames / content-type combos for upload tests.
UPLOAD_TESTS = [
    {
        "label": "html_as_image",
        "filename": "evil.html",
        "content_type": "image/jpeg",
        "content": b"<html><script>alert(1)</script></html>",
    },
    {
        "label": "double_extension",
        "filename": "evil.jpg.html",
        "content_type": "image/jpeg",
        "content": b"<html><script>alert(1)</script></html>",
    },
    {
        "label": "svg_with_script",
        "filename": "evil.svg",
        "content_type": "image/svg+xml",
        "content": (
            b'<svg xmlns="http://www.w3.org/2000/svg">'
            b"<script>alert(1)</script></svg>"
        ),
    },
    {
        "label": "path_traversal_filename",
        "filename": "../../../etc/passwd",
        "content_type": "text/plain",
        "content": b"path traversal test",
    },
    {
        "label": "null_byte_extension",
        "filename": "evil.php%00.jpg",
        "content_type": "image/jpeg",
        "content": b"<?php echo 'rce'; ?>",
    },
]


class InputValidationTest(BaseTest):
    """Test input handling for injection and upload vulnerabilities."""

    def run(self) -> List:
        logger.info("Starting input-validation tests")

        self._test_reflected_xss()
        self._test_stored_xss()
        self._test_sqli()
        self._test_nosql_injection()
        self._test_crlf_injection()
        self._test_file_upload()

        logger.info(
            "Input-validation tests complete: %d results", len(self.results)
        )
        return self.results

    # ------------------------------------------------------------------
    # XSS
    # ------------------------------------------------------------------

    def _test_reflected_xss(self) -> None:
        """Try reflected XSS via search/query parameters."""
        test_name = "input_validation:reflected_xss"
        search_endpoints = self._get_search_endpoints()

        if not search_endpoints:
            self.add_result(
                test_name=test_name,
                status="not_tested",
                severity="info",
                description="No search/query endpoints found for reflected XSS test.",
                evidence="No search endpoints in recon.",
                remediation="Identify search endpoints and re-test.",
            )
            return

        found = False
        for ep in search_endpoints:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            param = ep.get("param", "q") if isinstance(ep, dict) else "q"
            if not url:
                continue

            endpoint_timed_out = False
            for payload in XSS_PAYLOADS:
                try:
                    resp = self.http.get(
                        url,
                        params={param: payload},
                    )

                    # If the HTTP client returned a synthetic 408 (URL
                    # exceeded its timeout threshold), skip remaining
                    # payloads for this endpoint.
                    if resp.status_code == 408:
                        endpoint_timed_out = True
                        break

                    body = resp.text if hasattr(resp, "text") else ""

                    if payload in body:
                        self.add_result(
                            test_name=f"{test_name}:{url}",
                            status="exploited_verified",
                            severity="high",
                            description=(
                                f"Reflected XSS: payload echoed verbatim in "
                                f"response from {url}?{param}=..."
                            ),
                            evidence=(
                                f"Payload: {payload}\n"
                                f"Found in body (HTTP {resp.status_code})"
                            ),
                            remediation=(
                                "HTML-encode all user input before reflecting "
                                "it in responses. Implement Content-Security-Policy."
                            ),
                        )
                        found = True
                        break
                except Exception as exc:
                    # If the first request to this endpoint times out,
                    # skip remaining payloads to avoid wasting time.
                    if "Timeout" in type(exc).__name__ or "timeout" in str(exc).lower():
                        logger.warning(
                            "Endpoint %s timed out -- skipping remaining XSS payloads",
                            url,
                        )
                        endpoint_timed_out = True
                        break
                    logger.warning("Reflected XSS error on %s: %s", url, exc)

            if endpoint_timed_out:
                self.add_result(
                    test_name=f"{test_name}:{url}",
                    status="not_tested",
                    severity="info",
                    description=(
                        f"Reflected XSS not tested on {url}: endpoint "
                        f"timed out, remaining payloads skipped."
                    ),
                    evidence="Endpoint timeout",
                    remediation="Investigate endpoint availability and re-test.",
                )
                continue

            if found:
                break

        if not found:
            self.add_result(
                test_name=test_name,
                status="blocked",
                severity="info",
                description="No reflected XSS found in tested search endpoints.",
                evidence="Payloads not echoed verbatim.",
                remediation="No action needed.",
            )

    def _test_stored_xss(self) -> None:
        """Try stored XSS in profile fields (name, bio)."""
        test_name = "input_validation:stored_xss"
        profile_url = self.recon.get("profile_update_endpoint", "/api/profile")

        fields_to_test = ["name", "bio", "about", "description", "displayName"]

        found = False
        for field in fields_to_test:
            for payload in XSS_PAYLOADS[:4]:  # Use fewer payloads for stored tests.
                try:
                    resp = self.http.patch(
                        profile_url,
                        json={field: payload},
                    )
                    status = resp.status_code

                    if status in (400, 422):
                        # Server rejected the input -- good.
                        continue

                    if status == 200:
                        # Check if payload is stored and returned.
                        get_resp = self.http.get(profile_url)
                        get_body = get_resp.text if hasattr(get_resp, "text") else ""

                        if payload in get_body:
                            self.add_result(
                                test_name=f"{test_name}:{field}",
                                status="exploited_verified",
                                severity="high",
                                description=(
                                    f"Stored XSS: payload persisted in "
                                    f"'{field}' field and returned verbatim."
                                ),
                                evidence=(
                                    f"Field: {field}, Payload: {payload}\n"
                                    f"Returned in GET {profile_url}"
                                ),
                                remediation=(
                                    "Sanitize and encode all stored user input. "
                                    "Implement CSP headers."
                                ),
                            )
                            found = True
                            break
                except Exception as exc:
                    logger.warning(
                        "Stored XSS error on %s/%s: %s", profile_url, field, exc
                    )
            if found:
                break

        if not found:
            self.add_result(
                test_name=test_name,
                status="blocked",
                severity="info",
                description="No stored XSS found in profile fields.",
                evidence="Payloads either rejected or sanitized.",
                remediation="No action needed.",
            )

    # ------------------------------------------------------------------
    # SQL Injection
    # ------------------------------------------------------------------

    def _test_sqli(self) -> None:
        """Test SQL injection in login, search, and other input fields."""
        test_name = "input_validation:sqli"
        targets = self._get_injection_targets()

        found = False
        for target in targets:
            url = target["url"]
            method = target.get("method", "POST")
            fields = target.get("fields", [])

            for field in fields:
                for payload in SQLI_PAYLOADS:
                    try:
                        data = {field: payload}
                        if method.upper() == "POST":
                            resp = self.http.post(
                                url, json=data
                            )
                        else:
                            resp = self.http.get(
                                url, params=data
                            )

                        body = resp.text[:1000] if hasattr(resp, "text") else ""

                        if self._has_sqli_indicator(body):
                            self.add_result(
                                test_name=f"{test_name}:{url}:{field}",
                                status="exploited_verified"
                                if self._has_sql_error(body)
                                else "suspected_unverified",
                                severity="critical",
                                description=(
                                    f"SQL injection indicator in {url}, "
                                    f"field '{field}'. Payload: {payload}"
                                ),
                                evidence=f"HTTP {resp.status_code}, body: {body[:300]}",
                                remediation=(
                                    "Use parameterized queries / prepared "
                                    "statements. Never concatenate user input "
                                    "into SQL."
                                ),
                            )
                            found = True
                            break
                    except Exception as exc:
                        logger.warning(
                            "SQLi test error %s/%s: %s", url, field, exc
                        )
                if found:
                    break
            if found:
                break

        if not found:
            self.add_result(
                test_name=test_name,
                status="blocked",
                severity="info",
                description="No SQL injection indicators found.",
                evidence="No SQL errors or anomalous responses.",
                remediation="No action needed.",
            )

    # ------------------------------------------------------------------
    # NoSQL Injection
    # ------------------------------------------------------------------

    def _test_nosql_injection(self) -> None:
        """Test NoSQL (MongoDB-style) injection in login and API endpoints."""
        test_name = "input_validation:nosql_injection"
        login_url = self.recon.get("login_endpoint", "/api/auth/login")

        found = False
        for nosql_payload in NOSQL_PAYLOADS:
            payloads_to_try = [
                {"email": nosql_payload, "password": "anything"},
                {"email": "test@test.com", "password": nosql_payload},
            ]
            for payload in payloads_to_try:
                try:
                    resp = self.http.post(
                        login_url, json=payload
                    )
                    status = resp.status_code
                    body = resp.text[:500] if hasattr(resp, "text") else ""

                    # If the server returns 200 with auth data, that is bad.
                    if status == 200 and any(
                        tok in body.lower()
                        for tok in ['"token"', '"access_token"', '"jwt"']
                    ):
                        self.add_result(
                            test_name=test_name,
                            status="exploited_verified",
                            severity="critical",
                            description=(
                                f"NoSQL injection bypassed auth on {login_url}. "
                                f"Payload: {json.dumps(payload, default=str)}"
                            ),
                            evidence=f"HTTP {status}, body: {body[:300]}",
                            remediation=(
                                "Validate and sanitize input types. Reject "
                                "objects/arrays where strings are expected."
                            ),
                        )
                        found = True
                        break
                except Exception as exc:
                    logger.warning("NoSQL injection test error: %s", exc)
            if found:
                break

        if not found:
            self.add_result(
                test_name=test_name,
                status="blocked",
                severity="info",
                description="No NoSQL injection vulnerabilities found.",
                evidence="All NoSQL payloads rejected or returned non-200.",
                remediation="No action needed.",
            )

    # ------------------------------------------------------------------
    # CRLF / Header Injection
    # ------------------------------------------------------------------

    def _test_crlf_injection(self) -> None:
        """Test CRLF injection in input fields."""
        test_name = "input_validation:crlf_injection"
        targets = self._get_injection_targets()

        found = False
        for target in targets:
            url = target["url"]
            fields = target.get("fields", [])

            for field in fields:
                for payload in CRLF_PAYLOADS:
                    try:
                        resp = self.http.post(
                            url, json={field: payload}
                        )
                        # Check response headers for injected header.
                        resp_headers = getattr(resp, "headers", {})
                        if "Injected-Header" in str(resp_headers):
                            self.add_result(
                                test_name=f"{test_name}:{url}:{field}",
                                status="exploited_verified",
                                severity="high",
                                description=(
                                    f"CRLF injection: injected header "
                                    f"appeared in response from {url}, "
                                    f"field '{field}'."
                                ),
                                evidence=(
                                    f"Payload: {payload!r}\n"
                                    f"Response headers: {dict(resp_headers)}"
                                ),
                                remediation=(
                                    "Strip or reject CR/LF characters in all "
                                    "user input before including in headers."
                                ),
                            )
                            found = True
                            break
                    except Exception as exc:
                        logger.warning(
                            "CRLF test error %s/%s: %s", url, field, exc
                        )
                if found:
                    break
            if found:
                break

        if not found:
            self.add_result(
                test_name=test_name,
                status="blocked",
                severity="info",
                description="No CRLF injection found.",
                evidence="No injected headers in responses.",
                remediation="No action needed.",
            )

    # ------------------------------------------------------------------
    # File Upload
    # ------------------------------------------------------------------

    def _test_file_upload(self) -> None:
        """Test file upload endpoint with malicious payloads."""
        test_name = "input_validation:file_upload"
        upload_url = self.recon.get("upload_endpoint")
        if not upload_url:
            # Try common upload paths.
            candidates = [
                "/api/upload", "/api/photos/upload", "/api/files/upload",
                "/api/profile/photo", "/api/images",
            ]
            upload_url = candidates[0]  # Will test the first; others as fallback.
            for candidate in candidates:
                try:
                    resp = self.http.options(candidate)
                    if resp.status_code != 404:
                        upload_url = candidate
                        break
                except Exception:
                    continue

        for test_case in UPLOAD_TESTS:
            label = test_case["label"]
            try:
                files = {
                    "file": (
                        test_case["filename"],
                        test_case["content"],
                        test_case["content_type"],
                    )
                }
                resp = self.http.post(
                    upload_url, files=files
                )
                status = resp.status_code
                body = resp.text[:500] if hasattr(resp, "text") else ""

                if status == 200 or status == 201:
                    # Check if the server accepted the malicious file.
                    if "url" in body.lower() or "path" in body.lower():
                        self.add_result(
                            test_name=f"{test_name}:{label}",
                            status="exploited_verified",
                            severity="high",
                            description=(
                                f"Malicious upload accepted: {label} "
                                f"({test_case['filename']} as "
                                f"{test_case['content_type']})."
                            ),
                            evidence=f"HTTP {status}, body: {body[:300]}",
                            remediation=(
                                "Validate file content (not just Content-Type). "
                                "Reject dangerous extensions. Use allowlist."
                            ),
                        )
                    else:
                        self.add_result(
                            test_name=f"{test_name}:{label}",
                            status="suspected_unverified",
                            severity="medium",
                            description=(
                                f"Upload returned {status} for {label} but "
                                f"could not confirm file was stored."
                            ),
                            evidence=f"HTTP {status}, body: {body[:200]}",
                            remediation="Verify upload handling manually.",
                        )
                elif status in (400, 403, 415, 422):
                    self.add_result(
                        test_name=f"{test_name}:{label}",
                        status="blocked",
                        severity="info",
                        description=(
                            f"Malicious upload {label} rejected (HTTP {status})."
                        ),
                        evidence=f"HTTP {status}",
                        remediation="No action needed.",
                    )
                else:
                    self.add_result(
                        test_name=f"{test_name}:{label}",
                        status="not_tested",
                        severity="info",
                        description=(
                            f"Upload endpoint returned HTTP {status} for {label}."
                        ),
                        evidence=f"HTTP {status}",
                        remediation="Verify upload endpoint availability.",
                    )
            except Exception as exc:
                logger.warning("File upload test error (%s): %s", label, exc)
                self.add_result(
                    test_name=f"{test_name}:{label}",
                    status="not_tested",
                    severity="info",
                    description=f"Could not test upload {label}: {exc}",
                    evidence=str(exc),
                    remediation="Investigate.",
                )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_search_endpoints(self) -> List[Any]:
        """Return search/query endpoints from recon or defaults."""
        endpoints = self.recon.get("search_endpoints", [])
        if endpoints:
            return endpoints
        # Fallback to common patterns.
        return [
            {"url": "/api/search", "param": "q"},
            {"url": "/api/users/search", "param": "query"},
            {"url": "/search", "param": "q"},
        ]

    def _get_injection_targets(self) -> List[Dict[str, Any]]:
        """Return a list of endpoints+fields suitable for injection tests."""
        targets: List[Dict[str, Any]] = []

        # From recon forms.
        for form in self.recon.get("forms", []):
            url = form.get("action", "")
            fields = [
                f.get("name", "")
                for f in form.get("fields", [])
                if f.get("name")
            ]
            if url and fields:
                targets.append(
                    {"url": url, "method": form.get("method", "POST"), "fields": fields}
                )

        # Always include login.
        login_url = self.recon.get("login_endpoint", "/api/auth/login")
        targets.append(
            {"url": login_url, "method": "POST", "fields": ["email", "password"]}
        )

        # Search endpoints.
        for sep in self._get_search_endpoints():
            url = sep if isinstance(sep, str) else sep.get("url", "")
            param = sep.get("param", "q") if isinstance(sep, dict) else "q"
            if url:
                targets.append({"url": url, "method": "GET", "fields": [param]})

        return targets

    @staticmethod
    def _has_sqli_indicator(body: str) -> bool:
        """Check for SQL error messages or anomalous behaviour."""
        indicators = [
            "sql syntax", "mysql", "postgresql", "sqlite", "syntax error",
            "unclosed quotation", "unterminated string", "pg_query", "ORA-",
            "microsoft sql", "warning:", "error in your sql",
        ]
        lower = body.lower()
        return any(ind in lower for ind in indicators)

    @staticmethod
    def _has_sql_error(body: str) -> bool:
        """Stricter check: actual SQL error string present."""
        errors = [
            "sql syntax", "syntax error", "unclosed quotation",
            "unterminated string", "pg_query", "ORA-",
        ]
        lower = body.lower()
        return any(e in lower for e in errors)
