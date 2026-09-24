"""Admin access tests.

Probes for unauthorized access to administrative endpoints and
functionality, including path discovery, header injection of admin
roles, and privilege escalation through profile mutation.
"""

from __future__ import annotations

import logging
from typing import List

from tests import BaseTest

logger = logging.getLogger(__name__)

# Common admin paths to probe.
ADMIN_PATHS = [
    "/admin",
    "/#/admin",
    "/admin-panel",
    "/admin/dashboard",
    "/admin/users",
    "/api/admin",
    "/api/admin/users",
    "/api/admin/dashboard",
    "/api/admin/stats",
    "/api/admin/settings",
    "/api/admin/reports",
    "/api/users",
    "/api/users?limit=100",
    "/api/v1/admin",
    "/api/v2/admin",
    "/internal",
    "/internal/health",
    "/graphql",
    "/swagger",
    "/api-docs",
    "/docs",
]

# Headers that might trick a poorly-implemented role check.
ADMIN_HEADERS_SETS = [
    {"X-Admin": "true"},
    {"X-Role": "admin"},
    {"Role": "admin"},
    {"X-User-Role": "admin"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Forwarded-For": "127.0.0.1"},
]

# Payloads to attempt role escalation via profile update.
ROLE_ESCALATION_PAYLOADS = [
    {"role": "admin"},
    {"is_admin": True},
    {"isAdmin": True},
    {"user_type": "admin"},
    {"userType": "admin"},
    {"permissions": ["admin"]},
    {"role_id": 1},
    {"roleId": 1},
    {"group": "administrators"},
]


class AdminAccessTest(BaseTest):
    """Test for unauthorized admin-level access."""

    def run(self) -> List:
        logger.info("Starting admin-access tests")

        self._test_admin_paths()
        self._test_admin_paths_with_headers()
        self._test_recon_admin_url()
        self._test_role_escalation()
        self._test_admin_api_with_user_token()

        logger.info(
            "Admin-access tests complete: %d results", len(self.results)
        )
        return self.results

    # ------------------------------------------------------------------
    # Test groups
    # ------------------------------------------------------------------

    def _test_admin_paths(self) -> None:
        """Probe common admin paths without special tricks."""
        for path in ADMIN_PATHS:
            test_name = f"admin_access:path:{path}"
            try:
                # Try without auth first.
                resp = self.http.get(path)
                status = resp.status_code
                body = resp.text[:500] if hasattr(resp, "text") else ""

                if status == 200 and self._looks_like_admin(body):
                    self.add_result(
                        test_name=test_name,
                        status="exploited_verified",
                        severity="critical",
                        description=(
                            f"Admin path {path} accessible without auth "
                            f"(HTTP {status})."
                        ),
                        evidence=f"HTTP {status}, body: {body[:300]}",
                        remediation=(
                            "Restrict admin endpoints to authenticated admin "
                            "users only."
                        ),
                    )
                elif status == 200:
                    self.add_result(
                        test_name=test_name,
                        status="suspected_unverified",
                        severity="high",
                        description=(
                            f"Admin path {path} returned 200 without auth. "
                            f"Content may or may not be admin-level."
                        ),
                        evidence=f"HTTP {status}, body: {body[:200]}",
                        remediation="Manually verify content behind this path.",
                    )
                else:
                    self.add_result(
                        test_name=test_name,
                        status="blocked",
                        severity="info",
                        description=f"{path} returned HTTP {status}.",
                        evidence=f"HTTP {status}",
                        remediation="No action needed.",
                    )
            except Exception as exc:
                logger.warning("Error testing admin path %s: %s", path, exc)
                self.add_result(
                    test_name=test_name,
                    status="not_tested",
                    severity="info",
                    description=f"Could not test {path}: {exc}",
                    evidence=str(exc),
                    remediation="Investigate.",
                )

    def _test_admin_paths_with_headers(self) -> None:
        """Try accessing a protected admin path with spoofed headers."""
        target_paths = ["/admin", "/api/admin", "/api/admin/users"]
        for path in target_paths:
            for header_set in ADMIN_HEADERS_SETS:
                header_label = next(iter(header_set))
                test_name = (
                    f"admin_access:header_bypass:{path}:{header_label}"
                )
                try:
                    resp = self.http.get(
                        path, headers=header_set
                    )
                    status = resp.status_code
                    body = resp.text[:500] if hasattr(resp, "text") else ""

                    if status == 200 and self._looks_like_admin(body):
                        self.add_result(
                            test_name=test_name,
                            status="exploited_verified",
                            severity="critical",
                            description=(
                                f"Admin bypass via header {header_set} on "
                                f"{path} (HTTP {status})."
                            ),
                            evidence=f"HTTP {status}, headers: {header_set}, body: {body[:200]}",
                            remediation=(
                                "Never trust client-supplied role headers. "
                                "Authenticate and authorize server-side."
                            ),
                        )
                    else:
                        self.add_result(
                            test_name=test_name,
                            status="blocked",
                            severity="info",
                            description=(
                                f"Header bypass {header_label} on {path} "
                                f"rejected (HTTP {status})."
                            ),
                            evidence=f"HTTP {status}",
                            remediation="No action needed.",
                        )
                except Exception as exc:
                    logger.warning(
                        "Error in header bypass %s on %s: %s",
                        header_label, path, exc,
                    )
                    self.add_result(
                        test_name=test_name,
                        status="not_tested",
                        severity="info",
                        description=f"Could not test: {exc}",
                        evidence=str(exc),
                        remediation="Investigate.",
                    )

    def _test_recon_admin_url(self) -> None:
        """Try the admin URL discovered during recon, if any."""
        test_name = "admin_access:recon_admin_url"
        admin_url = self.recon.get("admin_url") or self.recon.get("admin_panel_url")
        if not admin_url:
            self.add_result(
                test_name=test_name,
                status="not_tested",
                severity="info",
                description="No admin URL found in recon data.",
                evidence="recon_data['admin_url'] is empty.",
                remediation="Run recon to discover admin panel location.",
            )
            return

        try:
            resp = self.http.get(admin_url)
            status = resp.status_code
            body = resp.text[:500] if hasattr(resp, "text") else ""

            if status == 200 and self._looks_like_admin(body):
                self.add_result(
                    test_name=test_name,
                    status="exploited_verified",
                    severity="critical",
                    description=(
                        f"Recon admin URL {admin_url} accessible without auth."
                    ),
                    evidence=f"HTTP {status}, body: {body[:300]}",
                    remediation="Restrict admin panel to authorized admins only.",
                )
            elif status in (401, 403):
                self.add_result(
                    test_name=test_name,
                    status="blocked",
                    severity="info",
                    description=(
                        f"Recon admin URL {admin_url} properly restricted "
                        f"(HTTP {status})."
                    ),
                    evidence=f"HTTP {status}",
                    remediation="No action needed.",
                )
            else:
                self.add_result(
                    test_name=test_name,
                    status="suspected_unverified",
                    severity="medium",
                    description=(
                        f"Recon admin URL returned HTTP {status}. "
                        f"Manual review advised."
                    ),
                    evidence=f"HTTP {status}, body: {body[:200]}",
                    remediation="Verify admin panel access controls.",
                )
        except Exception as exc:
            logger.warning("Error testing recon admin URL: %s", exc)
            self.add_result(
                test_name=test_name,
                status="not_tested",
                severity="info",
                description=f"Could not test recon admin URL: {exc}",
                evidence=str(exc),
                remediation="Investigate.",
            )

    def _test_role_escalation(self) -> None:
        """Attempt to escalate to admin by modifying the user profile."""
        test_name = "admin_access:role_escalation"
        profile_url = self.recon.get("profile_update_endpoint", "/api/profile")

        for payload in ROLE_ESCALATION_PAYLOADS:
            field = next(iter(payload))
            try:
                # PATCH or PUT the profile with an admin-role field.
                resp = self.http.patch(
                    profile_url, json=payload
                )
                status = resp.status_code
                body = resp.text[:500] if hasattr(resp, "text") else ""

                if status == 200 and self._role_changed(body, field):
                    self.add_result(
                        test_name=f"{test_name}:{field}",
                        status="exploited_verified",
                        severity="critical",
                        description=(
                            f"Role escalation: server accepted {payload} via "
                            f"profile update (HTTP {status})."
                        ),
                        evidence=f"HTTP {status}, body: {body[:300]}",
                        remediation=(
                            "Never allow clients to set their own role. "
                            "Whitelist mutable profile fields server-side."
                        ),
                    )
                    return
                elif status in (400, 403, 422):
                    self.add_result(
                        test_name=f"{test_name}:{field}",
                        status="blocked",
                        severity="info",
                        description=(
                            f"Role escalation via {field} rejected (HTTP {status})."
                        ),
                        evidence=f"HTTP {status}",
                        remediation="No action needed.",
                    )
                else:
                    self.add_result(
                        test_name=f"{test_name}:{field}",
                        status="suspected_unverified",
                        severity="medium",
                        description=(
                            f"Profile update with {field} returned {status}. "
                            f"Could not confirm escalation."
                        ),
                        evidence=f"HTTP {status}, body: {body[:200]}",
                        remediation="Manually verify role assignment.",
                    )
            except Exception as exc:
                logger.warning("Error in role escalation (%s): %s", field, exc)
                self.add_result(
                    test_name=f"{test_name}:{field}",
                    status="not_tested",
                    severity="info",
                    description=f"Could not test role escalation via {field}: {exc}",
                    evidence=str(exc),
                    remediation="Investigate.",
                )

    def _test_admin_api_with_user_token(self) -> None:
        """Try admin API endpoints with a regular user's auth token."""
        test_name = "admin_access:user_token_on_admin_api"
        admin_api_paths = [
            "/api/admin/users",
            "/api/admin/dashboard",
            "/api/admin/stats",
            "/api/admin/settings",
        ]

        token = self.config.get("auth_token", "")
        if not token:
            self.add_result(
                test_name=test_name,
                status="not_tested",
                severity="info",
                description="No auth token available for user-token admin test.",
                evidence="No token in config.",
                remediation="Provide a regular user token to test.",
            )
            return

        for path in admin_api_paths:
            try:
                resp = self.http.get(path)
                status = resp.status_code
                body = resp.text[:500] if hasattr(resp, "text") else ""

                if status == 200 and self._looks_like_admin(body):
                    self.add_result(
                        test_name=f"{test_name}:{path}",
                        status="exploited_verified",
                        severity="critical",
                        description=(
                            f"Regular user token granted access to admin "
                            f"endpoint {path} (HTTP {status})."
                        ),
                        evidence=f"HTTP {status}, body: {body[:300]}",
                        remediation=(
                            "Enforce role-based access control on admin "
                            "endpoints."
                        ),
                    )
                elif status in (401, 403):
                    self.add_result(
                        test_name=f"{test_name}:{path}",
                        status="blocked",
                        severity="info",
                        description=(
                            f"{path} correctly denied to regular user "
                            f"(HTTP {status})."
                        ),
                        evidence=f"HTTP {status}",
                        remediation="No action needed.",
                    )
                else:
                    self.add_result(
                        test_name=f"{test_name}:{path}",
                        status="blocked",
                        severity="info",
                        description=f"{path} returned HTTP {status}.",
                        evidence=f"HTTP {status}",
                        remediation="No action needed.",
                    )
            except Exception as exc:
                logger.warning("Error testing %s with user token: %s", path, exc)
                self.add_result(
                    test_name=f"{test_name}:{path}",
                    status="not_tested",
                    severity="info",
                    description=f"Could not test {path}: {exc}",
                    evidence=str(exc),
                    remediation="Investigate.",
                )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _looks_like_admin(body: str) -> bool:
        """Heuristic: does the response look like admin-level content?"""
        indicators = [
            "admin", "dashboard", "all users", "user management",
            "system settings", "total_users", "totalUsers",
            "admin_panel", "adminPanel", "statistics",
        ]
        lower = body.lower()
        return sum(1 for ind in indicators if ind.lower() in lower) >= 2

    @staticmethod
    def _role_changed(body: str, field: str) -> bool:
        """Check if the response confirms the role field was accepted."""
        lower = body.lower()
        return field.lower() in lower and "admin" in lower
