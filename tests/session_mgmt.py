"""Session management tests.

Validates cookie security attributes, session token entropy,
expiration, concurrent sessions, logout invalidation, token-in-URL
exposure, and session fixation.
"""

from __future__ import annotations

import logging
import math
import re
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs

from tests import BaseTest

logger = logging.getLogger(__name__)


class SessionMgmtTest(BaseTest):
    """Test suite for session management vulnerabilities."""

    MODULE_NAME = "session_mgmt"

    def run(self) -> List:
        logger.info("Starting session management tests")

        self._check_cookie_attributes()
        self._check_token_entropy()
        self._check_session_expiration()
        self._check_concurrent_sessions()
        self._check_logout_invalidation()
        self._check_token_in_url()
        self._check_session_fixation()

        logger.info(
            "Session management tests complete: %d results recorded",
            len(self.results),
        )
        return self.results

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _base_url(self) -> str:
        return self.config.get("target", {}).get("base_url", "")

    def _get_login_endpoint(self) -> Optional[str]:
        """Attempt to find a login endpoint from recon data."""
        forms = self.recon.get("forms_found", [])
        for form in forms:
            action = form.get("action_url", "") if isinstance(form, dict) else getattr(form, "action_url", "")
            if any(kw in action.lower() for kw in ["login", "signin", "auth", "session"]):
                return action

        api_endpoints = self.recon.get("api_endpoints", [])
        for ep in api_endpoints:
            ep_url = ep["url"] if isinstance(ep, dict) else ep
            if any(kw in ep_url.lower() for kw in ["login", "signin", "auth/token", "session"]):
                if ep_url.startswith("http"):
                    return ep_url
                return f"{self._base_url()}{ep_url}"

        return None

    def _get_test_credentials(self) -> Optional[Dict[str, str]]:
        """Retrieve test account credentials from config."""
        accounts = self.config.get("accounts", {})
        for name, acct in accounts.items():
            email = acct.get("email") if isinstance(acct, dict) else getattr(acct, "email", "")
            password = acct.get("password") if isinstance(acct, dict) else getattr(acct, "password", "")
            if email and password:
                return {"email": email, "password": password}
        return None

    def _login(self, endpoint: str, creds: Dict[str, str]) -> Optional[object]:
        """Perform a login request and return the response."""
        try:
            return self.http.post(endpoint, json=creds)
        except Exception as exc:
            logger.warning("Login request failed: %s", exc)
            return None

    def _extract_session_token(self, response) -> Optional[str]:
        """Try to extract a session/auth token from the response."""
        # Check cookies
        cookies = getattr(response, "cookies", {})
        for name in ("session", "sessionid", "sid", "token", "access_token", "jwt"):
            val = cookies.get(name)
            if val:
                return val

        # Check JSON body
        try:
            body = response.json()
            for key in ("token", "access_token", "jwt", "session_token", "sessionId"):
                if key in body:
                    return body[key]
        except Exception:
            pass

        # Check headers
        auth = response.headers.get("Authorization", "")
        if auth:
            return auth

        return None

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_cookie_attributes(self) -> None:
        """Verify that session cookies have HttpOnly, Secure, and SameSite flags."""
        logger.info("Checking cookie security attributes")
        base = self._base_url()
        try:
            resp = self.http.get(base)
            set_cookies = resp.headers.get("Set-Cookie", "")
            if not set_cookies:
                # Try login endpoint as well
                login_ep = self._get_login_endpoint()
                creds = self._get_test_credentials()
                if login_ep and creds:
                    resp = self._login(login_ep, creds)
                    if resp:
                        set_cookies = resp.headers.get("Set-Cookie", "")

            if not set_cookies:
                self.add_result(
                    test_name="Cookie Security Attributes",
                    test_module=self.MODULE_NAME,
                    status="not_tested",
                    severity="info",
                    description="No Set-Cookie headers found to evaluate.",
                    target_url=base,
                    expected_behavior="Session cookies should have HttpOnly, Secure, SameSite.",
                    actual_behavior="No cookies set in response.",
                    reproduction_steps=[f"GET {base}", "Check Set-Cookie header."],
                    evidence="",
                    remediation="If cookies are used, ensure security attributes are set.",
                    retest_description="Check Set-Cookie headers after authentication.",
                )
                return

            # Parse all Set-Cookie values (could be multiple)
            cookie_str = set_cookies if isinstance(set_cookies, str) else str(set_cookies)
            issues = []
            if "httponly" not in cookie_str.lower():
                issues.append("Missing HttpOnly flag")
            if "secure" not in cookie_str.lower():
                issues.append("Missing Secure flag")
            if "samesite" not in cookie_str.lower():
                issues.append("Missing SameSite attribute")
            elif "samesite=none" in cookie_str.lower():
                issues.append("SameSite=None (permissive)")

            status = "suspected_unverified" if issues else "blocked"
            severity = "medium" if issues else "info"
            self.add_result(
                test_name="Cookie Security Attributes",
                test_module=self.MODULE_NAME,
                status=status,
                severity=severity,
                description=f"{'Issues found' if issues else 'All attributes present'} in session cookies.",
                target_url=base,
                expected_behavior="Cookies should have HttpOnly, Secure, SameSite=Strict or Lax.",
                actual_behavior="; ".join(issues) if issues else "All security attributes present.",
                reproduction_steps=["Authenticate or visit the app.", "Inspect Set-Cookie headers."],
                evidence=cookie_str[:500],
                remediation="Set HttpOnly, Secure, and SameSite=Strict on all session cookies.",
                retest_description="Re-check Set-Cookie headers after fix.",
            )
        except Exception as exc:
            logger.warning("Error checking cookie attributes: %s", exc)
            self.add_result(
                test_name="Cookie Security Attributes",
                test_module=self.MODULE_NAME,
                status="not_tested",
                severity="info",
                description=f"Could not check cookie attributes: {exc}",
                target_url=base,
                expected_behavior="Cookies should have security attributes.",
                actual_behavior=f"Error: {exc}",
                reproduction_steps=["Retry request."],
                evidence=str(exc),
                remediation="N/A",
                retest_description="Retry when application is accessible.",
            )

    def _check_token_entropy(self) -> None:
        """Evaluate session token length and randomness."""
        logger.info("Checking session token entropy")
        login_ep = self._get_login_endpoint()
        creds = self._get_test_credentials()

        if not login_ep or not creds:
            self.add_result(
                test_name="Session Token Entropy",
                test_module=self.MODULE_NAME,
                status="not_tested",
                severity="info",
                description="No login endpoint or credentials available.",
                target_url=self._base_url(),
                expected_behavior="Session tokens should be at least 128 bits of entropy.",
                actual_behavior="Cannot obtain tokens without login endpoint/credentials.",
                reproduction_steps=["Configure test credentials and run recon."],
                evidence="",
                remediation="Ensure tokens use cryptographically secure random generation.",
                retest_description="Re-run with valid credentials.",
            )
            return

        tokens = []
        for _ in range(3):
            resp = self._login(login_ep, creds)
            if resp:
                token = self._extract_session_token(resp)
                if token:
                    tokens.append(token)
            time.sleep(0.5)

        if not tokens:
            self.add_result(
                test_name="Session Token Entropy",
                test_module=self.MODULE_NAME,
                status="not_tested",
                severity="info",
                description="Could not extract session tokens from login responses.",
                target_url=login_ep,
                expected_behavior="Login should return a session token.",
                actual_behavior="No token found in response cookies, body, or headers.",
                reproduction_steps=[f"POST {login_ep} with credentials.", "Check response for tokens."],
                evidence="",
                remediation="N/A",
                retest_description="Retry after verifying login endpoint.",
            )
            return

        # Evaluate entropy
        issues = []
        avg_len = sum(len(t) for t in tokens) / len(tokens)
        if avg_len < 20:
            issues.append(f"Token too short (avg {avg_len:.0f} chars, recommend >= 32)")

        # Check if all tokens are identical (not random)
        if len(set(tokens)) == 1 and len(tokens) > 1:
            issues.append("All tokens are identical - not randomly generated")

        # Simple character-set entropy estimate
        sample = tokens[0]
        charset_size = len(set(sample))
        entropy_bits = len(sample) * math.log2(max(charset_size, 2))
        if entropy_bits < 64:
            issues.append(f"Estimated entropy too low ({entropy_bits:.0f} bits, recommend >= 128)")

        status = "suspected_unverified" if issues else "blocked"
        severity = "high" if issues else "info"
        self.add_result(
            test_name="Session Token Entropy",
            test_module=self.MODULE_NAME,
            status=status,
            severity=severity,
            description=f"{'Weak token entropy' if issues else 'Token entropy appears adequate'}.",
            target_url=login_ep,
            expected_behavior="Tokens should be >= 128 bits entropy, unique per session.",
            actual_behavior="; ".join(issues) if issues else f"Avg length {avg_len:.0f}, estimated {entropy_bits:.0f} bits entropy.",
            reproduction_steps=["Login multiple times.", "Compare token values and lengths."],
            evidence=f"Tokens collected: {len(tokens)}, avg length: {avg_len:.0f}, unique: {len(set(tokens))}",
            remediation="Use a CSPRNG with at least 128 bits of output for session tokens.",
            retest_description="Login 3 times and compare token properties.",
        )

    def _check_session_expiration(self) -> None:
        """Test whether sessions expire after a period of inactivity."""
        logger.info("Checking session expiration")
        login_ep = self._get_login_endpoint()
        creds = self._get_test_credentials()

        if not login_ep or not creds:
            self.add_result(
                test_name="Session Expiration",
                test_module=self.MODULE_NAME,
                status="not_tested",
                severity="info",
                description="No login endpoint or credentials available.",
                target_url=self._base_url(),
                expected_behavior="Sessions should expire after a reasonable idle period.",
                actual_behavior="Cannot test without credentials.",
                reproduction_steps=["Provide test credentials."],
                evidence="",
                remediation="Implement session timeout.",
                retest_description="Re-run with valid credentials.",
            )
            return

        resp = self._login(login_ep, creds)
        if not resp:
            return

        token = self._extract_session_token(resp)
        if not token:
            return

        # Check cookie max-age / expires
        set_cookie = resp.headers.get("Set-Cookie", "")
        has_expiry = bool(
            re.search(r"(max-age|expires)\s*=", set_cookie, re.IGNORECASE)
        )

        if has_expiry:
            max_age_match = re.search(r"max-age\s*=\s*(\d+)", set_cookie, re.IGNORECASE)
            max_age_val = int(max_age_match.group(1)) if max_age_match else None
            long_lived = max_age_val is not None and max_age_val > 86400 * 7  # > 7 days

            if long_lived:
                self.add_result(
                    test_name="Session Expiration",
                    test_module=self.MODULE_NAME,
                    status="suspected_unverified",
                    severity="medium",
                    description=f"Session cookie has excessively long max-age ({max_age_val}s).",
                    target_url=login_ep,
                    expected_behavior="Session cookies should expire within hours to days.",
                    actual_behavior=f"max-age={max_age_val}s ({max_age_val // 86400} days).",
                    reproduction_steps=["Login and inspect Set-Cookie max-age."],
                    evidence=set_cookie[:300],
                    remediation="Set session timeout to a reasonable value (e.g., 1-24 hours).",
                    retest_description="Check max-age value after fix.",
                )
            else:
                self.add_result(
                    test_name="Session Expiration",
                    test_module=self.MODULE_NAME,
                    status="blocked",
                    severity="info",
                    description="Session cookie has a reasonable expiration.",
                    target_url=login_ep,
                    expected_behavior="Session should expire.",
                    actual_behavior=f"max-age={max_age_val}s." if max_age_val else "Expires header present.",
                    reproduction_steps=["Login and inspect Set-Cookie."],
                    evidence=set_cookie[:300],
                    remediation="N/A",
                    retest_description="Re-check after changes.",
                )
        else:
            # Session cookie (no explicit expiry) - acceptable if server-side timeout exists
            self.add_result(
                test_name="Session Expiration",
                test_module=self.MODULE_NAME,
                status="suspected_unverified",
                severity="low",
                description="No explicit expiration found in session cookie. Relies on browser session.",
                target_url=login_ep,
                expected_behavior="Session cookies should have explicit expiration.",
                actual_behavior="No max-age or expires directive found.",
                reproduction_steps=["Login and inspect Set-Cookie header."],
                evidence=set_cookie[:300] if set_cookie else "No Set-Cookie header",
                remediation="Set explicit max-age on session cookies. Implement server-side timeout.",
                retest_description="Re-check Set-Cookie for expiration directives.",
            )

    def _check_concurrent_sessions(self) -> None:
        """Check if multiple simultaneous sessions are allowed."""
        logger.info("Checking concurrent session handling")
        login_ep = self._get_login_endpoint()
        creds = self._get_test_credentials()

        if not login_ep or not creds:
            self.add_result(
                test_name="Concurrent Sessions",
                test_module=self.MODULE_NAME,
                status="not_tested",
                severity="info",
                description="No login endpoint or credentials available.",
                target_url=self._base_url(),
                expected_behavior="Application should limit concurrent sessions.",
                actual_behavior="Cannot test without credentials.",
                reproduction_steps=["Provide test credentials."],
                evidence="",
                remediation="Implement concurrent session limits.",
                retest_description="Re-run with valid credentials.",
            )
            return

        # Login twice, collect tokens
        resp1 = self._login(login_ep, creds)
        time.sleep(0.5)
        resp2 = self._login(login_ep, creds)

        if not resp1 or not resp2:
            return

        token1 = self._extract_session_token(resp1)
        token2 = self._extract_session_token(resp2)

        if not token1 or not token2:
            self.add_result(
                test_name="Concurrent Sessions",
                test_module=self.MODULE_NAME,
                status="not_tested",
                severity="info",
                description="Could not extract tokens to test concurrency.",
                target_url=login_ep,
                expected_behavior="Limited concurrent sessions.",
                actual_behavior="Token extraction failed.",
                reproduction_steps=["Login twice and compare tokens."],
                evidence="",
                remediation="N/A",
                retest_description="Retry with working login.",
            )
            return

        both_valid = True
        # Try to use the first token - if both work, concurrency is allowed
        api_endpoints = self.recon.get("api_endpoints", [])
        if api_endpoints:
            first_ep = api_endpoints[0]
            test_url = first_ep["url"] if isinstance(first_ep, dict) else first_ep
        else:
            test_url = f"{self._base_url()}/api/v1/profile"
        if not test_url.startswith("http"):
            test_url = f"{self._base_url()}{test_url}"

        try:
            r1 = self.http.get(test_url, headers={"Authorization": f"Bearer {token1}"})
            r2 = self.http.get(test_url, headers={"Authorization": f"Bearer {token2}"})
            both_valid = r1.status_code < 400 and r2.status_code < 400
        except Exception:
            both_valid = token1 != token2  # Different tokens suggest both are active

        self.add_result(
            test_name="Concurrent Sessions",
            test_module=self.MODULE_NAME,
            status="suspected_unverified" if both_valid else "blocked",
            severity="low" if both_valid else "info",
            description=f"{'Multiple concurrent sessions allowed' if both_valid else 'Previous session may be invalidated on new login'}.",
            target_url=login_ep,
            expected_behavior="Previous session should be invalidated when a new one is created (or limited).",
            actual_behavior=f"Token1 != Token2: {token1 != token2}. Both valid: {both_valid}.",
            reproduction_steps=["Login twice with the same account.", "Test both tokens."],
            evidence=f"Token1 length: {len(token1)}, Token2 length: {len(token2)}, same: {token1 == token2}",
            remediation="Implement session concurrency limits or invalidate old sessions on new login.",
            retest_description="Login twice and verify first session is invalidated.",
        )

    def _check_logout_invalidation(self) -> None:
        """Verify that the session token is invalidated after logout."""
        logger.info("Checking logout token invalidation")
        login_ep = self._get_login_endpoint()
        creds = self._get_test_credentials()

        if not login_ep or not creds:
            self.add_result(
                test_name="Logout Token Invalidation",
                test_module=self.MODULE_NAME,
                status="not_tested",
                severity="info",
                description="No login endpoint or credentials available.",
                target_url=self._base_url(),
                expected_behavior="Tokens should be invalidated after logout.",
                actual_behavior="Cannot test without credentials.",
                reproduction_steps=["Provide test credentials."],
                evidence="",
                remediation="Invalidate tokens server-side on logout.",
                retest_description="Re-run with valid credentials.",
            )
            return

        resp = self._login(login_ep, creds)
        if not resp:
            return

        token = self._extract_session_token(resp)
        if not token:
            return

        # Find logout endpoint
        logout_candidates = [
            f"{self._base_url()}/api/v1/auth/logout",
            f"{self._base_url()}/api/v1/logout",
            f"{self._base_url()}/auth/logout",
            f"{self._base_url()}/logout",
        ]

        api_endpoints = self.recon.get("api_endpoints", [])
        for ep in api_endpoints:
            ep_url = ep["url"] if isinstance(ep, dict) else ep
            if "logout" in ep_url.lower():
                url = ep_url if ep_url.startswith("http") else f"{self._base_url()}{ep_url}"
                if url not in logout_candidates:
                    logout_candidates.insert(0, url)

        logout_done = False
        for logout_url in logout_candidates:
            try:
                lr = self.http.post(
                    logout_url,
                    headers={"Authorization": f"Bearer {token}"},
                )
                if lr.status_code < 400:
                    logout_done = True
                    break
            except Exception:
                continue

        if not logout_done:
            self.add_result(
                test_name="Logout Token Invalidation",
                test_module=self.MODULE_NAME,
                status="not_tested",
                severity="info",
                description="Could not find a working logout endpoint.",
                target_url=self._base_url(),
                expected_behavior="A logout endpoint should exist.",
                actual_behavior=f"Tried {len(logout_candidates)} logout URLs, none succeeded.",
                reproduction_steps=["Find and call the logout endpoint."],
                evidence="",
                remediation="Ensure a logout endpoint is available.",
                retest_description="Locate logout endpoint and retry.",
            )
            return

        # Now try to use the old token
        if api_endpoints:
            first_ep = api_endpoints[0]
            test_url = first_ep["url"] if isinstance(first_ep, dict) else first_ep
        else:
            test_url = f"{self._base_url()}/api/v1/profile"
        if not test_url.startswith("http"):
            test_url = f"{self._base_url()}{test_url}"

        try:
            check = self.http.get(
                test_url, headers={"Authorization": f"Bearer {token}"}
            )
            still_valid = check.status_code < 400
        except Exception:
            still_valid = False

        self.add_result(
            test_name="Logout Token Invalidation",
            test_module=self.MODULE_NAME,
            status="suspected_unverified" if still_valid else "blocked",
            severity="high" if still_valid else "info",
            description=f"{'Token still valid after logout' if still_valid else 'Token properly invalidated after logout'}.",
            target_url=logout_url,
            expected_behavior="Token should return 401/403 after logout.",
            actual_behavior=f"Post-logout request returned HTTP {check.status_code}.",
            reproduction_steps=[
                "Login and obtain a token.",
                "Call logout endpoint.",
                "Reuse the old token on a protected endpoint.",
            ],
            evidence=f"Post-logout status: {check.status_code}",
            remediation="Invalidate session tokens server-side upon logout (token blacklist or DB delete).",
            retest_description="Login, logout, then reuse token and expect 401.",
        )

    def _check_token_in_url(self) -> None:
        """Check if session tokens are ever passed in URLs."""
        logger.info("Checking for session tokens in URLs")
        pages = self.recon.get("pages_found", [])

        found_in_url = []
        token_patterns = re.compile(
            r"[?&](token|session|sid|access_token|jwt|api_key)=([^&]+)",
            re.IGNORECASE,
        )

        for page_url in pages[:20]:
            match = token_patterns.search(page_url)
            if match:
                found_in_url.append(f"{match.group(1)}=*** in {page_url[:100]}")

        # Also check any redirect locations from login
        login_ep = self._get_login_endpoint()
        creds = self._get_test_credentials()
        if login_ep and creds:
            try:
                resp = self._login(login_ep, creds)
                if resp:
                    location = resp.headers.get("Location", "")
                    if token_patterns.search(location):
                        found_in_url.append(f"Token in redirect Location: {location[:100]}")
            except Exception:
                pass

        status = "suspected_unverified" if found_in_url else "blocked"
        severity = "medium" if found_in_url else "info"
        self.add_result(
            test_name="Session Token in URL",
            test_module=self.MODULE_NAME,
            status=status,
            severity=severity,
            description=f"{'Session tokens found in URLs' if found_in_url else 'No session tokens found in URLs'}.",
            target_url=self._base_url(),
            expected_behavior="Session tokens should never be passed in URL parameters.",
            actual_behavior="; ".join(found_in_url) if found_in_url else "No tokens in URLs.",
            reproduction_steps=["Inspect crawled URLs for token parameters.", "Check login redirect Location header."],
            evidence="\n".join(found_in_url) if found_in_url else "",
            remediation="Pass tokens in cookies or Authorization headers, never in URLs.",
            retest_description="Re-crawl and check for token parameters in URLs.",
        )

    def _check_session_fixation(self) -> None:
        """Test for session fixation vulnerability."""
        logger.info("Checking for session fixation")
        login_ep = self._get_login_endpoint()
        creds = self._get_test_credentials()

        if not login_ep or not creds:
            self.add_result(
                test_name="Session Fixation",
                test_module=self.MODULE_NAME,
                status="not_tested",
                severity="info",
                description="No login endpoint or credentials available.",
                target_url=self._base_url(),
                expected_behavior="Session ID should change after login.",
                actual_behavior="Cannot test without credentials.",
                reproduction_steps=["Provide test credentials."],
                evidence="",
                remediation="Regenerate session ID after authentication.",
                retest_description="Re-run with valid credentials.",
            )
            return

        # Get a session token BEFORE login
        try:
            pre_resp = self.http.get(self._base_url())
        except Exception as exc:
            logger.warning("Cannot fetch pre-login page: %s", exc)
            return

        pre_token = self._extract_session_token(pre_resp)

        # Now login
        resp = self._login(login_ep, creds)
        if not resp:
            return

        post_token = self._extract_session_token(resp)

        if not pre_token or not post_token:
            self.add_result(
                test_name="Session Fixation",
                test_module=self.MODULE_NAME,
                status="not_tested",
                severity="info",
                description="Could not extract pre- and post-login tokens for comparison.",
                target_url=login_ep,
                expected_behavior="Session ID should change after login.",
                actual_behavior="Token extraction incomplete.",
                reproduction_steps=["Get pre-login cookie, login, compare cookies."],
                evidence="",
                remediation="Regenerate session ID on login.",
                retest_description="Retry after verifying cookie handling.",
            )
            return

        same_token = pre_token == post_token
        self.add_result(
            test_name="Session Fixation",
            test_module=self.MODULE_NAME,
            status="suspected_unverified" if same_token else "blocked",
            severity="high" if same_token else "info",
            description=f"{'Session ID unchanged after login - possible fixation' if same_token else 'Session ID changed after login - fixation mitigated'}.",
            target_url=login_ep,
            expected_behavior="Session ID must change after authentication.",
            actual_behavior=f"Pre-login token == post-login token: {same_token}.",
            reproduction_steps=[
                "Visit the site and capture the session cookie.",
                "Login and compare the new session cookie.",
            ],
            evidence=f"Pre-login token length: {len(pre_token)}, Post-login token length: {len(post_token)}, identical: {same_token}",
            remediation="Regenerate session ID (new token) upon successful authentication.",
            retest_description="Compare pre- and post-login session tokens.",
        )
