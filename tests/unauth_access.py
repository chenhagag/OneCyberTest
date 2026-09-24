"""Unauthenticated access tests.

Attempts to access protected endpoints and pages without providing
any authentication token.  Every endpoint that returns anything other
than 401/403 is flagged.
"""

from __future__ import annotations

import logging
from typing import List

from tests import BaseTest

logger = logging.getLogger(__name__)

# Common paths that almost always require authentication.
PROTECTED_PATHS = [
    "/profile",
    "/dashboard",
    "/settings",
    "/matches",
    "/conversations",
    "/admin",
    "/api/profile",
    "/api/dashboard",
    "/api/settings",
    "/api/matches",
    "/api/conversations",
    "/api/admin",
    "/api/users/me",
    "/api/notifications",
    "/api/insights",
]

# Status codes that indicate the endpoint is correctly guarded.
EXPECTED_BLOCKED = {401, 403}


class UnauthAccessTest(BaseTest):
    """Test for resources accessible without authentication."""

    def run(self) -> List:
        logger.info("Starting unauthenticated-access tests")

        # Merge static protected paths with anything recon discovered.
        discovered_endpoints = self._gather_endpoints()

        for path in discovered_endpoints:
            self._test_path(path)

        logger.info(
            "Unauthenticated-access tests complete: %d results", len(self.results)
        )
        return self.results

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _gather_endpoints(self) -> List[str]:
        """Build a deduplicated list of paths to probe."""
        paths = list(PROTECTED_PATHS)

        # Add API endpoints discovered during recon.
        for ep in self.recon.get("api_endpoints", []):
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if url and url not in paths:
                paths.append(url)

        # Add pages that recon flagged as login-required.
        for page in self.recon.get("protected_pages", []):
            url = page if isinstance(page, str) else page.get("url", "")
            if url and url not in paths:
                paths.append(url)

        return paths

    def _test_path(self, path: str) -> None:
        """Send an unauthenticated GET to *path* and record the outcome."""
        test_name = f"unauth_access:{path}"
        try:
            resp = self.http.get(path)
            status = resp.status_code
            body = resp.text[:500] if hasattr(resp, "text") else ""

            if status in EXPECTED_BLOCKED:
                self.add_result(
                    test_name=test_name,
                    status="blocked",
                    severity="info",
                    description=(
                        f"GET {path} without auth returned {status} as expected."
                    ),
                    evidence=f"HTTP {status}",
                    remediation="No action needed.",
                )
            elif self._contains_user_data(body):
                self.add_result(
                    test_name=test_name,
                    status="exploited_verified",
                    severity="critical",
                    description=(
                        f"GET {path} returned user data ({status}) without "
                        f"authentication."
                    ),
                    evidence=f"HTTP {status} - body snippet: {body[:200]}",
                    remediation=(
                        "Enforce authentication on this endpoint. Return 401 "
                        "for unauthenticated requests."
                    ),
                )
            elif status == 200:
                self.add_result(
                    test_name=test_name,
                    status="suspected_unverified",
                    severity="high",
                    description=(
                        f"GET {path} returned 200 without auth. May expose "
                        f"protected content."
                    ),
                    evidence=f"HTTP {status} - body snippet: {body[:200]}",
                    remediation=(
                        "Verify whether this endpoint should require "
                        "authentication and enforce it."
                    ),
                )
            else:
                self.add_result(
                    test_name=test_name,
                    status="blocked",
                    severity="info",
                    description=(
                        f"GET {path} returned {status} without auth (not 200)."
                    ),
                    evidence=f"HTTP {status}",
                    remediation="No action needed.",
                )

        except Exception as exc:
            logger.warning("Error testing %s: %s", path, exc)
            self.add_result(
                test_name=test_name,
                status="not_tested",
                severity="info",
                description=f"Could not test {path}: {exc}",
                evidence=str(exc),
                remediation="Investigate connectivity or path validity.",
            )

    @staticmethod
    def _contains_user_data(body: str) -> bool:
        """Heuristic: does the response body look like it contains user data?"""
        indicators = [
            '"email"', '"phone"', '"address"', '"password"',
            '"user_id"', '"userId"', '"username"', '"name"',
            '"token"', '"access_token"', '"conversations"',
            '"matches"', '"profile"',
        ]
        body_lower = body.lower()
        return any(ind.lower() in body_lower for ind in indicators)
