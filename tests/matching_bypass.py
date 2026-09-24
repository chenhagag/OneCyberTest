"""Matching/dating process bypass tests.

Tests specific to the One dating application's matching workflow.
Attempts to bypass onboarding, access restricted profiles, skip
payment gates, and manipulate the matching algorithm.
"""

from __future__ import annotations

import logging
import time
from typing import Dict, List, Optional

from tests import BaseTest

logger = logging.getLogger(__name__)


class MatchingBypassTest(BaseTest):
    """Test suite for matching process bypass vulnerabilities."""

    MODULE_NAME = "matching_bypass"

    def run(self) -> List:
        logger.info("Starting matching/dating process bypass tests")

        auth_headers = self._get_auth_headers()

        self._test_onboarding_skip(auth_headers)
        self._test_access_without_profile(auth_headers)
        self._test_matching_manipulation(auth_headers)
        self._test_hidden_profile_access(auth_headers)
        self._test_message_without_match(auth_headers)
        self._test_subscription_bypass(auth_headers)

        logger.info(
            "Matching bypass tests complete: %d results recorded",
            len(self.results),
        )
        return self.results

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _base_url(self) -> str:
        return self.config.get("target", {}).get("base_url", "")

    def _get_auth_headers(self) -> Dict[str, str]:
        """Obtain auth headers by logging in with test credentials."""
        accounts = self.config.get("accounts", {})
        for name, acct in accounts.items():
            email = acct.get("email") if isinstance(acct, dict) else getattr(acct, "email", "")
            password = acct.get("password") if isinstance(acct, dict) else getattr(acct, "password", "")
            if not email or not password:
                continue

            login_candidates = self._discover_endpoints("login", "signin", "auth/token")
            if not login_candidates:
                login_candidates = [
                    f"{self._base_url()}/api/v1/auth/login",
                    f"{self._base_url()}/api/v1/login",
                ]

            for login_url in login_candidates:
                try:
                    resp = self.http.post(
                        login_url, json={"email": email, "password": password}
                    )
                    if resp.status_code < 400:
                        try:
                            body = resp.json()
                            for key in ("token", "access_token", "jwt", "session_token"):
                                if key in body:
                                    return {"Authorization": f"Bearer {body[key]}"}
                        except Exception:
                            pass
                except Exception:
                    continue
        return {}

    def _discover_endpoints(self, *keywords: str) -> List[str]:
        """Find API endpoints from recon data matching any of the keywords."""
        api_endpoints = self.recon.get("api_endpoints", [])
        results = []
        for ep in api_endpoints:
            ep_url = ep["url"] if isinstance(ep, dict) else ep
            ep_lower = ep_url.lower()
            for kw in keywords:
                if kw in ep_lower:
                    url = ep_url if ep_url.startswith("http") else f"{self._base_url()}{ep_url}"
                    results.append(url)
                    break
        return results

    def _safe_request(self, method: str, url: str, headers: Dict[str, str] = None,
                      json_body: dict = None) -> Optional[object]:
        """Perform an HTTP request with error handling."""
        try:
            if method.upper() == "GET":
                return self.http.get(url, headers=headers or {})
            elif method.upper() == "POST":
                return self.http.post(url, json=json_body or {}, headers=headers or {})
            elif method.upper() == "PUT":
                return self.http.put(url, json=json_body or {}, headers=headers or {})
            elif method.upper() == "PATCH":
                return self.http.patch(url, json=json_body or {}, headers=headers or {})
        except Exception as exc:
            logger.warning("%s %s failed: %s", method, url, exc)
            return None

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _test_onboarding_skip(self, auth_headers: Dict[str, str]) -> None:
        """Try to skip onboarding steps by directly accessing later-stage endpoints."""
        logger.info("Testing onboarding step bypass")

        # Endpoints that should only be accessible after completing onboarding
        late_stage_paths = [
            "/api/v1/matches",
            "/api/v1/discover",
            "/api/v1/swipe",
            "/api/v1/recommendations",
            "/api/v1/conversations",
            "/api/v1/feed",
        ]

        # Also check recon-discovered endpoints
        discovered = self._discover_endpoints(
            "match", "discover", "swipe", "recommend", "conversation", "feed"
        )
        all_urls = list(set(
            [f"{self._base_url()}{p}" for p in late_stage_paths] + discovered
        ))

        accessible = []
        blocked = []

        for url in all_urls[:8]:  # Cap requests
            resp = self._safe_request("GET", url, headers=auth_headers)
            if resp is None:
                continue

            if resp.status_code == 200:
                # Check if the response contains actual data vs a redirect/error
                try:
                    body = resp.json()
                    has_data = bool(body) and not body.get("error")
                except Exception:
                    has_data = len(resp.text) > 50

                if has_data:
                    accessible.append(f"{url} (HTTP {resp.status_code})")
                else:
                    blocked.append(f"{url} (HTTP {resp.status_code}, empty/error)")
            elif resp.status_code in (302, 307):
                location = resp.headers.get("Location", "")
                if "onboarding" in location.lower() or "profile" in location.lower():
                    blocked.append(f"{url} (redirected to onboarding)")
                else:
                    accessible.append(f"{url} (redirected to {location[:60]})")
            else:
                blocked.append(f"{url} (HTTP {resp.status_code})")

        if accessible:
            self.add_result(
                test_name="Onboarding Step Bypass",
                test_module=self.MODULE_NAME,
                status="suspected_unverified",
                severity="medium",
                description=f"{len(accessible)} late-stage endpoint(s) accessible without completing onboarding.",
                target_url=self._base_url(),
                expected_behavior="Users should complete all onboarding steps before accessing matching features.",
                actual_behavior=f"Accessible: {'; '.join(accessible[:5])}",
                reproduction_steps=[
                    "Create a new account but do not complete onboarding.",
                    "Directly access matching/conversation endpoints.",
                ],
                evidence="\n".join(accessible),
                remediation="Enforce onboarding completion check middleware on all protected endpoints.",
                retest_description="Access late-stage endpoints with an incomplete profile.",
            )
        else:
            self.add_result(
                test_name="Onboarding Step Bypass",
                test_module=self.MODULE_NAME,
                status="blocked",
                severity="info",
                description="Late-stage endpoints appear to require onboarding completion.",
                target_url=self._base_url(),
                expected_behavior="Endpoints blocked without completed onboarding.",
                actual_behavior=f"All {len(blocked)} tested endpoint(s) returned non-200 or redirect.",
                reproduction_steps=["Attempt to access matching endpoints without full profile."],
                evidence="\n".join(blocked[:5]) if blocked else "No endpoints tested.",
                remediation="N/A",
                retest_description="Re-test with incomplete profile.",
            )

    def _test_access_without_profile(self, auth_headers: Dict[str, str]) -> None:
        """Try to access matches/conversations without a completed profile."""
        logger.info("Testing access to matches without completed profile")

        # Try to access the matches endpoint with minimal/no profile data
        match_endpoints = self._discover_endpoints("match", "recommendation")
        if not match_endpoints:
            match_endpoints = [f"{self._base_url()}/api/v1/matches"]

        for url in match_endpoints[:2]:
            resp = self._safe_request("GET", url, headers=auth_headers)
            if resp is None:
                self.add_result(
                    test_name="Access Matches Without Profile",
                    test_module=self.MODULE_NAME,
                    status="not_tested",
                    severity="info",
                    description=f"Could not reach {url}.",
                    target_url=url,
                    expected_behavior="Matches should require a completed profile.",
                    actual_behavior="Request failed.",
                    reproduction_steps=[f"GET {url} without completed profile."],
                    evidence="",
                    remediation="N/A",
                    retest_description="Retry when endpoint is accessible.",
                )
                continue

            has_matches = False
            try:
                body = resp.json()
                # Check if actual match data was returned
                if isinstance(body, list) and len(body) > 0:
                    has_matches = True
                elif isinstance(body, dict):
                    for key in ("matches", "results", "data", "items"):
                        val = body.get(key)
                        if isinstance(val, list) and len(val) > 0:
                            has_matches = True
                            break
            except Exception:
                pass

            self.add_result(
                test_name="Access Matches Without Profile",
                test_module=self.MODULE_NAME,
                status="suspected_unverified" if has_matches else "blocked",
                severity="medium" if has_matches else "info",
                description=(
                    f"{'Match data returned without profile verification' if has_matches else 'No match data returned'} "
                    f"(HTTP {resp.status_code})."
                ),
                target_url=url,
                expected_behavior="No matches should be returned without a completed profile.",
                actual_behavior=f"HTTP {resp.status_code}, match data present: {has_matches}.",
                reproduction_steps=[f"GET {url} with auth but without completed profile."],
                evidence=resp.text[:300] if has_matches else "",
                remediation="Validate profile completion status before returning match results.",
                retest_description=f"GET {url} without profile and check response.",
            )

    def _test_matching_manipulation(self, auth_headers: Dict[str, str]) -> None:
        """Try to manipulate matching by sending unexpected profile data."""
        logger.info("Testing matching algorithm manipulation")

        profile_endpoints = self._discover_endpoints("profile", "user/me", "account")
        if not profile_endpoints:
            profile_endpoints = [
                f"{self._base_url()}/api/v1/profile",
                f"{self._base_url()}/api/v1/user/me",
            ]

        # Manipulation payloads: unusual values that might confuse matching
        manipulation_payloads = [
            {
                "label": "extreme_age",
                "data": {"age": 999, "birthdate": "1900-01-01"},
            },
            {
                "label": "location_spoof",
                "data": {"latitude": 0.0, "longitude": 0.0, "location": ""},
            },
            {
                "label": "negative_values",
                "data": {"age": -1, "distance_preference": -100},
            },
            {
                "label": "type_confusion",
                "data": {"age": "not_a_number", "gender": 12345, "verified": "true"},
            },
        ]

        for payload_info in manipulation_payloads[:3]:  # Cap at 3 attempts
            label = payload_info["label"]
            data = payload_info["data"]

            for url in profile_endpoints[:1]:
                # Try PATCH first (partial update), then PUT
                resp = self._safe_request("PATCH", url, headers=auth_headers, json_body=data)
                if resp is None or resp.status_code == 405:
                    resp = self._safe_request("PUT", url, headers=auth_headers, json_body=data)

                if resp is None:
                    continue

                accepted = resp.status_code in (200, 201, 204)
                validated = resp.status_code in (400, 422)

                if accepted:
                    # Check if the server actually stored the bad data
                    check = self._safe_request("GET", url, headers=auth_headers)
                    stored_bad = False
                    if check and check.status_code == 200:
                        try:
                            profile = check.json()
                            # Check if any manipulation value persisted
                            for key, val in data.items():
                                if key in str(profile) and str(val) in str(profile):
                                    stored_bad = True
                                    break
                        except Exception:
                            pass

                    self.add_result(
                        test_name=f"Matching Algorithm Manipulation ({label})",
                        test_module=self.MODULE_NAME,
                        status="suspected_unverified" if stored_bad else "blocked",
                        severity="medium" if stored_bad else "info",
                        description=(
                            f"{'Server accepted and stored invalid profile data' if stored_bad else 'Server accepted request but may have sanitized data'} "
                            f"for {label} payload."
                        ),
                        target_url=url,
                        expected_behavior="Server should validate and reject invalid profile data.",
                        actual_behavior=f"HTTP {resp.status_code}, bad data stored: {stored_bad}.",
                        reproduction_steps=[
                            f"PATCH/PUT {url} with payload: {data}",
                            "GET profile and check if values persisted.",
                        ],
                        evidence=f"Payload: {data}",
                        remediation="Implement strict server-side validation for all profile fields.",
                        retest_description=f"Send {label} payload and verify rejection.",
                    )
                elif validated:
                    self.add_result(
                        test_name=f"Matching Algorithm Manipulation ({label})",
                        test_module=self.MODULE_NAME,
                        status="blocked",
                        severity="info",
                        description=f"Server properly rejected {label} manipulation payload (HTTP {resp.status_code}).",
                        target_url=url,
                        expected_behavior="Invalid data should be rejected.",
                        actual_behavior=f"HTTP {resp.status_code} - validation error returned.",
                        reproduction_steps=[f"PATCH/PUT {url} with payload: {data}"],
                        evidence=resp.text[:300],
                        remediation="N/A",
                        retest_description=f"Send {label} payload and confirm rejection.",
                    )

    def _test_hidden_profile_access(self, auth_headers: Dict[str, str]) -> None:
        """Try to view profiles that should be hidden (blocked users, non-matching)."""
        logger.info("Testing hidden/blocked profile access")

        # Try to access arbitrary user profiles by ID
        profile_by_id_paths = [
            "/api/v1/users/{id}",
            "/api/v1/profiles/{id}",
            "/api/v1/user/{id}",
            "/api/v1/profile/{id}",
        ]

        # Also check recon-discovered endpoints
        discovered = self._discover_endpoints("user", "profile")
        for ep in discovered:
            if "{" not in ep and "me" not in ep.lower():
                profile_by_id_paths.insert(0, ep + "/999")

        test_ids = ["1", "2", "999", "admin"]

        accessible_profiles = []

        for path_template in profile_by_id_paths[:3]:
            for test_id in test_ids[:2]:  # Limit to 2 IDs per path
                url = f"{self._base_url()}{path_template}".replace("{id}", test_id)
                resp = self._safe_request("GET", url, headers=auth_headers)
                if resp is None:
                    continue

                if resp.status_code == 200:
                    try:
                        body = resp.json()
                        has_profile = any(
                            k in body for k in ("name", "email", "username", "bio", "profile", "user")
                        ) if isinstance(body, dict) else bool(body)
                    except Exception:
                        has_profile = len(resp.text) > 50

                    if has_profile:
                        accessible_profiles.append(f"{url} (HTTP 200)")

        if accessible_profiles:
            self.add_result(
                test_name="Hidden Profile Access",
                test_module=self.MODULE_NAME,
                status="suspected_unverified",
                severity="high",
                description=f"{len(accessible_profiles)} profile(s) accessible by direct ID enumeration.",
                target_url=self._base_url(),
                expected_behavior="Users should only see profiles they are matched with or that pass filter criteria.",
                actual_behavior=f"Profiles accessible: {'; '.join(accessible_profiles[:5])}",
                reproduction_steps=[
                    "Enumerate user IDs (1, 2, 999, etc.).",
                    "GET /api/v1/users/<id> with valid auth token.",
                ],
                evidence="\n".join(accessible_profiles),
                remediation=(
                    "Implement authorization checks: only return profiles the user is allowed to view. "
                    "Use UUIDs instead of sequential IDs."
                ),
                retest_description="Access profiles by ID and verify authorization enforcement.",
            )
        else:
            self.add_result(
                test_name="Hidden Profile Access",
                test_module=self.MODULE_NAME,
                status="blocked",
                severity="info",
                description="Could not access profiles by direct ID enumeration.",
                target_url=self._base_url(),
                expected_behavior="Arbitrary profile access should be blocked.",
                actual_behavior="All attempted profile accesses returned non-200 or empty.",
                reproduction_steps=["Try to access /api/v1/users/<id> with various IDs."],
                evidence="",
                remediation="N/A",
                retest_description="Re-test profile access by ID.",
            )

    def _test_message_without_match(self, auth_headers: Dict[str, str]) -> None:
        """Try to send messages to users without having a match."""
        logger.info("Testing message sending without match")

        message_endpoints = self._discover_endpoints("message", "chat", "conversation")
        if not message_endpoints:
            message_endpoints = [
                f"{self._base_url()}/api/v1/messages",
                f"{self._base_url()}/api/v1/conversations",
            ]

        # Try sending a message to an arbitrary user
        payloads = [
            {"recipient_id": "1", "message": "test", "content": "test"},
            {"to": "1", "text": "test"},
            {"user_id": "999", "body": "test"},
        ]

        for url in message_endpoints[:2]:
            for payload in payloads[:1]:  # One payload per endpoint
                resp = self._safe_request("POST", url, headers=auth_headers, json_body=payload)
                if resp is None:
                    continue

                sent = resp.status_code in (200, 201)

                if sent:
                    self.add_result(
                        test_name="Message Without Match",
                        test_module=self.MODULE_NAME,
                        status="suspected_unverified",
                        severity="high",
                        description=f"Message sent to unmatched user via {url} (HTTP {resp.status_code}).",
                        target_url=url,
                        expected_behavior="Messaging should require an active match between users.",
                        actual_behavior=f"HTTP {resp.status_code} - message appears to have been accepted.",
                        reproduction_steps=[
                            f"POST {url} with body: {payload}",
                            "Check if the message was delivered.",
                        ],
                        evidence=resp.text[:300],
                        remediation="Verify match status server-side before allowing messages.",
                        retest_description=f"Send message to unmatched user via {url}.",
                    )
                else:
                    self.add_result(
                        test_name="Message Without Match",
                        test_module=self.MODULE_NAME,
                        status="blocked",
                        severity="info",
                        description=f"Server rejected message to unmatched user (HTTP {resp.status_code}).",
                        target_url=url,
                        expected_behavior="Message to unmatched user should be rejected.",
                        actual_behavior=f"HTTP {resp.status_code}.",
                        reproduction_steps=[f"POST {url} with body: {payload}"],
                        evidence=resp.text[:200],
                        remediation="N/A",
                        retest_description=f"Retry sending message to unmatched user.",
                    )
                break  # One attempt per endpoint is enough

    def _test_subscription_bypass(self, auth_headers: Dict[str, str]) -> None:
        """Try to bypass payment/subscription gates."""
        logger.info("Testing subscription/payment bypass")

        # Endpoints that might be behind a paywall
        premium_paths = [
            "/api/v1/premium/features",
            "/api/v1/subscription",
            "/api/v1/likes/unlimited",
            "/api/v1/boost",
            "/api/v1/super-like",
            "/api/v1/see-who-likes",
            "/api/v1/rewind",
            "/api/v1/passport",  # Location change
        ]

        discovered = self._discover_endpoints(
            "premium", "subscription", "boost", "super", "unlimited", "payment", "plan"
        )
        all_urls = list(set(
            [f"{self._base_url()}{p}" for p in premium_paths] + discovered
        ))

        accessible_premium = []
        blocked_premium = []

        for url in all_urls[:8]:
            resp = self._safe_request("GET", url, headers=auth_headers)
            if resp is None:
                continue

            if resp.status_code == 200:
                try:
                    body = resp.json()
                    is_paywalled = False
                    if isinstance(body, dict):
                        # Check if response indicates a paywall
                        for key in ("requires_premium", "premium_required", "upgrade", "subscribe"):
                            if key in str(body).lower():
                                is_paywalled = True
                                break
                    if not is_paywalled:
                        accessible_premium.append(f"{url} (HTTP 200)")
                    else:
                        blocked_premium.append(f"{url} (paywall message in response)")
                except Exception:
                    if len(resp.text) > 50:
                        accessible_premium.append(f"{url} (HTTP 200, non-JSON)")
            elif resp.status_code in (402, 403):
                blocked_premium.append(f"{url} (HTTP {resp.status_code})")
            else:
                blocked_premium.append(f"{url} (HTTP {resp.status_code})")

        # Also try to directly modify subscription status
        sub_update_endpoints = self._discover_endpoints("subscription", "plan")
        for url in sub_update_endpoints[:1]:
            upgrade_payloads = [
                {"plan": "premium", "status": "active"},
                {"subscription_type": "premium", "paid": True},
            ]
            for payload in upgrade_payloads[:1]:
                resp = self._safe_request("PUT", url, headers=auth_headers, json_body=payload)
                if resp and resp.status_code in (200, 201):
                    accessible_premium.append(
                        f"{url} (subscription update accepted, HTTP {resp.status_code})"
                    )

        if accessible_premium:
            self.add_result(
                test_name="Subscription/Payment Bypass",
                test_module=self.MODULE_NAME,
                status="suspected_unverified",
                severity="high",
                description=f"{len(accessible_premium)} premium feature(s) accessible without valid subscription.",
                target_url=self._base_url(),
                expected_behavior="Premium features should require an active paid subscription.",
                actual_behavior=f"Accessible: {'; '.join(accessible_premium[:5])}",
                reproduction_steps=[
                    "Access premium endpoints with a free account.",
                    "Try to update subscription status via API.",
                ],
                evidence="\n".join(accessible_premium),
                remediation=(
                    "Enforce subscription validation server-side for all premium features. "
                    "Never trust client-side subscription status."
                ),
                retest_description="Access premium features with free account and verify paywall.",
            )
        else:
            self.add_result(
                test_name="Subscription/Payment Bypass",
                test_module=self.MODULE_NAME,
                status="blocked",
                severity="info",
                description="Premium features appear to be properly gated behind subscription.",
                target_url=self._base_url(),
                expected_behavior="Premium features require subscription.",
                actual_behavior=f"All {len(blocked_premium)} tested endpoint(s) blocked or paywalled.",
                reproduction_steps=["Access premium endpoints with free account."],
                evidence="\n".join(blocked_premium[:5]) if blocked_premium else "No endpoints tested.",
                remediation="N/A",
                retest_description="Re-test premium access with free account.",
            )
