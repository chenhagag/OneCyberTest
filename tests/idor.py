"""Insecure Direct Object Reference (IDOR) tests.

For every API endpoint that takes an ID parameter, tries sequential
enumeration and cross-user access to determine whether authorization
checks are enforced at the object level.
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any, Dict, List, Optional

from tests import BaseTest

logger = logging.getLogger(__name__)

# Resource types to probe and their typical API patterns.
RESOURCE_PATTERNS = [
    {"name": "user_profile", "paths": ["/api/users/{id}", "/api/profile/{id}"]},
    {"name": "conversation", "paths": ["/api/conversations/{id}", "/api/chats/{id}"]},
    {"name": "message", "paths": ["/api/messages/{id}", "/api/conversations/{id}/messages"]},
    {"name": "photo", "paths": ["/api/photos/{id}", "/api/users/{id}/photos"]},
    {"name": "match", "paths": ["/api/matches/{id}"]},
    {"name": "insight", "paths": ["/api/insights/{id}", "/api/users/{id}/insights"]},
]

# Regex to spot an ID placeholder in a URL.
_ID_RE = re.compile(r"\{id\}")


class IdorTest(BaseTest):
    """Test for Insecure Direct Object Reference vulnerabilities."""

    def run(self) -> List:
        logger.info("Starting IDOR tests")

        endpoints = self._gather_endpoints()
        for ep in endpoints:
            self._test_endpoint(ep)

        logger.info("IDOR tests complete: %d results", len(self.results))
        return self.results

    # ------------------------------------------------------------------
    # Endpoint discovery
    # ------------------------------------------------------------------

    def _gather_endpoints(self) -> List[Dict[str, Any]]:
        """Merge static resource patterns with recon-discovered endpoints."""
        endpoints: List[Dict[str, Any]] = []

        # Static patterns.
        for rp in RESOURCE_PATTERNS:
            for path_template in rp["paths"]:
                endpoints.append(
                    {"name": rp["name"], "path_template": path_template}
                )

        # Recon-discovered endpoints that contain an ID-like segment.
        for ep in self.recon.get("api_endpoints", []):
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if not url:
                continue
            # Detect numeric or UUID path segments.
            if re.search(r"/\d+", url) or re.search(
                r"/[0-9a-f]{8}-[0-9a-f]{4}-", url, re.I
            ):
                # Normalise the discovered URL into a template.
                template = re.sub(
                    r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                    "/{id}",
                    url,
                    flags=re.I,
                )
                template = re.sub(r"/\d+", "/{id}", template)
                endpoints.append({"name": "recon_discovered", "path_template": template})

        return endpoints

    # ------------------------------------------------------------------
    # Core test logic
    # ------------------------------------------------------------------

    def _test_endpoint(self, ep: Dict[str, Any]) -> None:
        """Run IDOR probes against a single endpoint template."""
        name = ep["name"]
        template = ep["path_template"]
        test_name = f"idor:{name}:{template}"

        # Determine what IDs to use.
        own_id = self._get_own_id()
        other_id = self._get_other_user_id()

        # Build list of IDs to try.
        ids_to_try = self._generate_test_ids(own_id, other_id)

        if not ids_to_try:
            self.add_result(
                test_name=test_name,
                status="not_tested",
                severity="info",
                description=f"No IDs available to test {template}.",
                evidence="No own_id or other_id in config/recon.",
                remediation="Provide user IDs for IDOR testing.",
            )
            return

        for test_id_info in ids_to_try:
            self._probe_id(test_name, template, test_id_info)

    def _probe_id(
        self,
        test_name: str,
        template: str,
        id_info: Dict[str, Any],
    ) -> None:
        """Make a single request substituting *id_info* into the template."""
        test_id = str(id_info["id"])
        label = id_info["label"]
        path = _ID_RE.sub(test_id, template)

        try:
            resp = self.http.get(path)
            status = resp.status_code
            body = resp.text[:500] if hasattr(resp, "text") else ""

            if status in (401, 403, 404):
                self.add_result(
                    test_name=f"{test_name}:{label}",
                    status="blocked",
                    severity="info",
                    description=(
                        f"Access to {path} ({label}) correctly denied "
                        f"(HTTP {status})."
                    ),
                    evidence=f"HTTP {status}",
                    remediation="No action needed.",
                )
            elif status == 200:
                is_foreign = id_info.get("is_foreign", False)
                if is_foreign and self._contains_data(body):
                    self.add_result(
                        test_name=f"{test_name}:{label}",
                        status="exploited_verified",
                        severity="critical",
                        description=(
                            f"IDOR: Accessed {path} ({label}) and received "
                            f"data belonging to another user."
                        ),
                        evidence=f"HTTP {status}, body: {body[:300]}",
                        remediation=(
                            "Implement object-level authorization. Verify the "
                            "requesting user owns the resource."
                        ),
                    )
                elif is_foreign:
                    self.add_result(
                        test_name=f"{test_name}:{label}",
                        status="suspected_unverified",
                        severity="high",
                        description=(
                            f"IDOR: {path} ({label}) returned 200 for a "
                            f"foreign ID. Could not confirm data leakage."
                        ),
                        evidence=f"HTTP {status}, body: {body[:200]}",
                        remediation=(
                            "Manually verify whether the response contains "
                            "another user's data."
                        ),
                    )
                else:
                    # Accessing own resource is expected.
                    pass
            else:
                self.add_result(
                    test_name=f"{test_name}:{label}",
                    status="blocked",
                    severity="info",
                    description=(
                        f"{path} ({label}) returned HTTP {status}."
                    ),
                    evidence=f"HTTP {status}",
                    remediation="No action needed.",
                )
        except Exception as exc:
            logger.warning("Error probing %s: %s", path, exc)
            self.add_result(
                test_name=f"{test_name}:{label}",
                status="not_tested",
                severity="info",
                description=f"Could not probe {path}: {exc}",
                evidence=str(exc),
                remediation="Investigate.",
            )

    # ------------------------------------------------------------------
    # ID generation helpers
    # ------------------------------------------------------------------

    def _generate_test_ids(
        self,
        own_id: Optional[str],
        other_id: Optional[str],
    ) -> List[Dict[str, Any]]:
        """Build a list of IDs to substitute into URL templates."""
        ids: List[Dict[str, Any]] = []

        if own_id:
            ids.append({"id": own_id, "label": "own_id", "is_foreign": False})

            # Sequential enumeration around own ID.
            if own_id.isdigit():
                numeric = int(own_id)
                for offset in (1, -1, 100, -100):
                    candidate = numeric + offset
                    if candidate > 0:
                        ids.append(
                            {
                                "id": str(candidate),
                                "label": f"own_id{'+' if offset > 0 else ''}{offset}",
                                "is_foreign": True,
                            }
                        )

        if other_id:
            ids.append(
                {"id": other_id, "label": "other_user_id", "is_foreign": True}
            )

        # Try a random UUID to see if the endpoint is guessable.
        ids.append(
            {
                "id": str(uuid.uuid4()),
                "label": "random_uuid",
                "is_foreign": True,
            }
        )

        # Try trivially low IDs (common in sequential DBs).
        if not own_id or not own_id.isdigit() or int(own_id) > 5:
            for low in (1, 2):
                ids.append(
                    {"id": str(low), "label": f"low_id_{low}", "is_foreign": True}
                )

        return ids

    def _get_own_id(self) -> Optional[str]:
        """Retrieve the authenticated user's ID from recon or config."""
        return (
            self.recon.get("own_user_id")
            or self.config.get("own_user_id")
            or self.recon.get("user_id")
        )

    def _get_other_user_id(self) -> Optional[str]:
        """Retrieve a second user's ID for cross-user tests."""
        return (
            self.recon.get("other_user_id")
            or self.config.get("other_user_id")
            or self.recon.get("test_user_2_id")
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _contains_data(body: str) -> bool:
        indicators = [
            '"email"', '"phone"', '"name"', '"bio"', '"user_id"',
            '"userId"', '"message"', '"content"', '"photo"',
            '"match"', '"conversation"', '"insight"',
        ]
        lower = body.lower()
        return any(ind.lower() in lower for ind in indicators)
