"""Rate limiting tests.

Verifies that the application enforces rate limits on login attempts,
API endpoints, and expensive operations such as search, AI chat, and
file uploads.

IMPORTANT: This module deliberately uses very low request counts (3-5)
to avoid causing any denial-of-service impact.  It is NOT a load test.
"""

from __future__ import annotations

import logging
import time
from typing import Dict, List, Optional, Tuple

from tests import BaseTest

logger = logging.getLogger(__name__)

# Maximum rapid requests per endpoint category.
_MAX_LOGIN_ATTEMPTS = 5
_MAX_API_ATTEMPTS = 5
_MAX_EXPENSIVE_ATTEMPTS = 3


class RateLimitingTest(BaseTest):
    """Test suite for rate limiting enforcement."""

    MODULE_NAME = "rate_limiting"

    def run(self) -> List:
        logger.info("Starting rate limiting tests")

        self._test_login_rate_limit()
        self._test_api_rate_limit()
        self._test_expensive_operations()

        logger.info(
            "Rate limiting tests complete: %d results recorded",
            len(self.results),
        )
        return self.results

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _base_url(self) -> str:
        return self.config.get("target", {}).get("base_url", "")

    def _detect_rate_limit(self, responses: list) -> Tuple[bool, List[str]]:
        """Analyze a list of HTTP responses for rate-limiting indicators.

        Returns (rate_limited: bool, indicators: list[str]).
        """
        indicators: List[str] = []

        status_codes = [r.status_code for r in responses if r is not None]

        # 429 Too Many Requests
        count_429 = status_codes.count(429)
        if count_429 > 0:
            indicators.append(f"Received {count_429} HTTP 429 responses")

        # Check for increasing delays (response times)
        times = [
            getattr(r, "elapsed", None)
            for r in responses
            if r is not None
        ]
        elapsed_secs = []
        for t in times:
            if t is not None:
                try:
                    elapsed_secs.append(t.total_seconds())
                except Exception:
                    pass

        if len(elapsed_secs) >= 3:
            first_half_avg = sum(elapsed_secs[: len(elapsed_secs) // 2]) / max(
                len(elapsed_secs) // 2, 1
            )
            second_half_avg = sum(elapsed_secs[len(elapsed_secs) // 2 :]) / max(
                len(elapsed_secs) - len(elapsed_secs) // 2, 1
            )
            if second_half_avg > first_half_avg * 2 and second_half_avg > 1.0:
                indicators.append(
                    f"Increasing response times detected "
                    f"(first half avg: {first_half_avg:.2f}s, "
                    f"second half avg: {second_half_avg:.2f}s)"
                )

        # Check for captcha or account lockout in response body
        for r in responses:
            if r is None:
                continue
            body_lower = r.text.lower()
            if "captcha" in body_lower or "recaptcha" in body_lower:
                indicators.append("CAPTCHA challenge detected in response")
                break
            if "locked" in body_lower or "too many" in body_lower:
                indicators.append("Account lockout or 'too many' message detected")
                break

        # Check Retry-After header
        for r in responses:
            if r is None:
                continue
            retry_after = r.headers.get("Retry-After")
            if retry_after:
                indicators.append(f"Retry-After header present: {retry_after}")
                break

        rate_limited = len(indicators) > 0
        return rate_limited, indicators

    def _find_login_endpoint(self) -> Optional[str]:
        """Locate a login endpoint from recon data."""
        api_endpoints = self.recon.get("api_endpoints", [])
        for ep in api_endpoints:
            ep_url = ep["url"] if isinstance(ep, dict) else ep
            if any(kw in ep_url.lower() for kw in ["login", "signin", "auth/token"]):
                return ep_url if ep_url.startswith("http") else f"{self._base_url()}{ep_url}"

        forms = self.recon.get("forms_found", [])
        for form in forms:
            action = form.get("action_url", "") if isinstance(form, dict) else getattr(form, "action_url", "")
            if any(kw in action.lower() for kw in ["login", "signin", "auth"]):
                return action

        # Fallback
        return f"{self._base_url()}/api/v1/auth/login"

    def _find_api_endpoints(self) -> List[str]:
        """Return a small set of API endpoints to test."""
        api_endpoints = self.recon.get("api_endpoints", [])
        result = []
        for ep in api_endpoints[:5]:
            ep_url = ep["url"] if isinstance(ep, dict) else ep
            url = ep_url if ep_url.startswith("http") else f"{self._base_url()}{ep_url}"
            result.append(url)
        if not result:
            result.append(f"{self._base_url()}/api/v1/profile")
        return result

    def _find_expensive_endpoints(self) -> List[Dict[str, str]]:
        """Identify expensive operations like search, AI chat, image upload."""
        api_endpoints = self.recon.get("api_endpoints", [])
        expensive = []
        keywords = {
            "search": "GET",
            "chat": "POST",
            "ai": "POST",
            "upload": "POST",
            "image": "POST",
            "export": "GET",
            "report": "GET",
        }

        for ep in api_endpoints:
            ep_url = ep["url"] if isinstance(ep, dict) else ep
            ep_lower = ep_url.lower()
            for kw, method in keywords.items():
                if kw in ep_lower:
                    url = ep_url if ep_url.startswith("http") else f"{self._base_url()}{ep_url}"
                    expensive.append({"url": url, "method": method, "type": kw})
                    break

        return expensive[:3]  # Cap at 3

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _test_login_rate_limit(self) -> None:
        """Send rapid login attempts with wrong password."""
        logger.info("Testing login endpoint rate limiting (%d attempts)", _MAX_LOGIN_ATTEMPTS)
        login_ep = self._find_login_endpoint()

        if not login_ep:
            self.add_result(
                test_name="Login Rate Limiting",
                test_module=self.MODULE_NAME,
                status="not_tested",
                severity="info",
                description="No login endpoint found.",
                target_url=self._base_url(),
                expected_behavior="Login endpoint should enforce rate limiting.",
                actual_behavior="Could not locate login endpoint.",
                reproduction_steps=["Discover login endpoint via recon."],
                evidence="",
                remediation="N/A",
                retest_description="Re-run after recon discovers login endpoint.",
            )
            return

        responses = []
        payload = {
            "email": "ratelimit_test@example.com",
            "password": "WrongPassword123!",
        }

        for i in range(_MAX_LOGIN_ATTEMPTS):
            try:
                resp = self.http.post(login_ep, json=payload)
                responses.append(resp)
                logger.debug(
                    "Login attempt %d/%d: HTTP %d",
                    i + 1, _MAX_LOGIN_ATTEMPTS, resp.status_code,
                )
            except Exception as exc:
                logger.warning("Login attempt %d failed: %s", i + 1, exc)
                responses.append(None)
            # No delay - we want to test rapid-fire behavior

        rate_limited, indicators = self._detect_rate_limit(
            [r for r in responses if r is not None]
        )

        status_summary = ", ".join(
            str(r.status_code) for r in responses if r is not None
        )

        self.add_result(
            test_name="Login Rate Limiting",
            test_module=self.MODULE_NAME,
            status="blocked" if rate_limited else "suspected_unverified",
            severity="info" if rate_limited else "high",
            description=(
                f"{'Rate limiting detected' if rate_limited else 'No rate limiting detected'} "
                f"after {_MAX_LOGIN_ATTEMPTS} rapid login attempts."
            ),
            target_url=login_ep,
            expected_behavior="After 3-5 failed logins, the server should rate-limit or lock the account.",
            actual_behavior=(
                f"Status codes: [{status_summary}]. "
                f"{'Indicators: ' + '; '.join(indicators) if indicators else 'No rate limiting indicators found.'}"
            ),
            reproduction_steps=[
                f"POST {login_ep} with wrong credentials {_MAX_LOGIN_ATTEMPTS} times rapidly.",
                "Check for HTTP 429, Retry-After, CAPTCHA, or account lockout.",
            ],
            evidence="; ".join(indicators) if indicators else f"All responses: [{status_summary}]",
            remediation=(
                "Implement rate limiting on login endpoint (e.g., 5 attempts per minute). "
                "Consider progressive delays or temporary account lockout."
            ),
            retest_description=f"Send {_MAX_LOGIN_ATTEMPTS} rapid login attempts and check for 429/lockout.",
        )

    def _test_api_rate_limit(self) -> None:
        """Send rapid requests to API endpoints."""
        logger.info("Testing API endpoint rate limiting (%d attempts)", _MAX_API_ATTEMPTS)
        endpoints = self._find_api_endpoints()

        for ep_url in endpoints[:2]:  # Test max 2 endpoints
            responses = []
            for i in range(_MAX_API_ATTEMPTS):
                try:
                    resp = self.http.get(ep_url)
                    responses.append(resp)
                    logger.debug(
                        "API request %d/%d to %s: HTTP %d",
                        i + 1, _MAX_API_ATTEMPTS, ep_url, resp.status_code,
                    )
                except Exception as exc:
                    logger.warning("API request %d to %s failed: %s", i + 1, ep_url, exc)
                    responses.append(None)

            valid_responses = [r for r in responses if r is not None]
            if not valid_responses:
                continue

            rate_limited, indicators = self._detect_rate_limit(valid_responses)
            status_summary = ", ".join(str(r.status_code) for r in valid_responses)

            self.add_result(
                test_name="API Rate Limiting",
                test_module=self.MODULE_NAME,
                status="blocked" if rate_limited else "suspected_unverified",
                severity="info" if rate_limited else "medium",
                description=(
                    f"{'Rate limiting detected' if rate_limited else 'No rate limiting detected'} "
                    f"on {ep_url} after {_MAX_API_ATTEMPTS} rapid requests."
                ),
                target_url=ep_url,
                expected_behavior="API should throttle excessive requests.",
                actual_behavior=(
                    f"Status codes: [{status_summary}]. "
                    f"{'Indicators: ' + '; '.join(indicators) if indicators else 'No throttling detected.'}"
                ),
                reproduction_steps=[
                    f"GET {ep_url} {_MAX_API_ATTEMPTS} times rapidly.",
                    "Check for HTTP 429 or Retry-After header.",
                ],
                evidence="; ".join(indicators) if indicators else f"All responses: [{status_summary}]",
                remediation="Implement API rate limiting (e.g., token bucket or sliding window).",
                retest_description=f"Send {_MAX_API_ATTEMPTS} rapid requests to {ep_url}.",
            )

    def _test_expensive_operations(self) -> None:
        """Test rate limiting on expensive operations (search, chat, upload)."""
        logger.info("Testing expensive operation rate limiting (%d attempts)", _MAX_EXPENSIVE_ATTEMPTS)
        expensive = self._find_expensive_endpoints()

        if not expensive:
            self.add_result(
                test_name="Expensive Operation Rate Limiting",
                test_module=self.MODULE_NAME,
                status="not_tested",
                severity="info",
                description="No expensive operation endpoints (search, chat, upload) found.",
                target_url=self._base_url(),
                expected_behavior="Expensive operations should have stricter rate limits.",
                actual_behavior="No matching endpoints discovered.",
                reproduction_steps=["Run recon to discover search/chat/upload endpoints."],
                evidence="",
                remediation="N/A",
                retest_description="Re-run after endpoint discovery.",
            )
            return

        for ep_info in expensive:
            url = ep_info["url"]
            method = ep_info["method"]
            ep_type = ep_info["type"]

            responses = []
            # Build a minimal request body for POST endpoints
            body = {}
            if ep_type == "search":
                body = {"query": "test", "q": "test"}
            elif ep_type in ("chat", "ai"):
                body = {"message": "hello"}
            elif ep_type in ("upload", "image"):
                body = {}  # Skip actual file upload - just test the endpoint

            for i in range(_MAX_EXPENSIVE_ATTEMPTS):
                try:
                    if method == "POST":
                        resp = self.http.post(url, json=body)
                    else:
                        resp = self.http.get(url, params={"q": "test"} if ep_type == "search" else None)
                    responses.append(resp)
                    logger.debug(
                        "%s request %d/%d to %s: HTTP %d",
                        ep_type, i + 1, _MAX_EXPENSIVE_ATTEMPTS, url, resp.status_code,
                    )
                except Exception as exc:
                    logger.warning("%s request %d failed: %s", ep_type, i + 1, exc)
                    responses.append(None)

            valid_responses = [r for r in responses if r is not None]
            if not valid_responses:
                continue

            rate_limited, indicators = self._detect_rate_limit(valid_responses)
            status_summary = ", ".join(str(r.status_code) for r in valid_responses)

            self.add_result(
                test_name=f"Expensive Operation Rate Limiting ({ep_type})",
                test_module=self.MODULE_NAME,
                status="blocked" if rate_limited else "suspected_unverified",
                severity="info" if rate_limited else "medium",
                description=(
                    f"{'Rate limiting detected' if rate_limited else 'No rate limiting detected'} "
                    f"on {ep_type} endpoint after {_MAX_EXPENSIVE_ATTEMPTS} rapid requests."
                ),
                target_url=url,
                expected_behavior=f"{ep_type.title()} endpoint should have strict rate limits.",
                actual_behavior=(
                    f"Status codes: [{status_summary}]. "
                    f"{'Indicators: ' + '; '.join(indicators) if indicators else 'No throttling detected.'}"
                ),
                reproduction_steps=[
                    f"{method} {url} {_MAX_EXPENSIVE_ATTEMPTS} times rapidly.",
                    "Check for HTTP 429, CAPTCHA, or throttling.",
                ],
                evidence="; ".join(indicators) if indicators else f"All responses: [{status_summary}]",
                remediation=(
                    f"Implement stricter rate limits on {ep_type} operations. "
                    "Consider per-user quotas and cost-based throttling."
                ),
                retest_description=f"Send {_MAX_EXPENSIVE_ATTEMPTS} rapid {ep_type} requests.",
            )
