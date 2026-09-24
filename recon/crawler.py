"""Web crawler for reconnaissance - discovers pages, forms, scripts, and links."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


@dataclass
class FormInfo:
    """Represents a discovered HTML form."""
    action_url: str
    method: str
    page_url: str
    inputs: List[Dict[str, Optional[str]]] = field(default_factory=list)


@dataclass
class ReconResult:
    """Aggregated results from a crawl session."""
    pages_found: List[str] = field(default_factory=list)
    forms_found: List[FormInfo] = field(default_factory=list)
    scripts_found: List[str] = field(default_factory=list)
    images_found: List[str] = field(default_factory=list)
    external_links: List[str] = field(default_factory=list)


class ReconCrawler:
    """Crawls a target website to discover pages, forms, scripts, and resources.

    Args:
        http_client: An HTTP client instance (from core.http_client) that
            enforces allowlist and rate-limiting.
        config: Application configuration dict (parsed from config.yaml).
    """

    def __init__(self, http_client: Any, config: Dict[str, Any]) -> None:
        self.http_client = http_client
        self.config = config

        # Crawl depth defaults to 3 unless overridden in config.
        self.max_depth: int = int(
            config.get("crawler", {}).get("max_depth", 3)
        )

        # Build the set of allowed domains from config.
        allowed = config.get("target", {}).get("allowed_domains", [])
        self.allowed_domains: Set[str] = set(allowed)

        # State kept across a single crawl invocation.
        self._visited: Set[str] = set()
        self._result: ReconResult = ReconResult()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def crawl(self, base_url: str) -> ReconResult:
        """Crawl *base_url* up to ``self.max_depth`` levels deep.

        Returns a :class:`ReconResult` containing all discovered assets.
        """
        self._visited = set()
        self._result = ReconResult()

        # Ensure the base domain is always considered allowed.
        base_domain = urlparse(base_url).netloc
        self.allowed_domains.add(base_domain)

        self._crawl_page(base_url, depth=0)

        logger.info(
            "Crawl complete: %d pages, %d forms, %d scripts, %d images, %d external links",
            len(self._result.pages_found),
            len(self._result.forms_found),
            len(self._result.scripts_found),
            len(self._result.images_found),
            len(self._result.external_links),
        )
        return self._result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_allowed(self, url: str) -> bool:
        """Return True if *url* belongs to an allowed domain."""
        domain = urlparse(url).netloc
        return domain in self.allowed_domains

    def _normalize_url(self, base: str, href: str) -> str:
        """Resolve *href* against *base* and strip the fragment."""
        full = urljoin(base, href)
        parsed = urlparse(full)
        # Drop the fragment so we don't visit the same page twice.
        return parsed._replace(fragment="").geturl()

    def _crawl_page(self, url: str, depth: int) -> None:
        """Recursively fetch and parse a single page."""
        if depth > self.max_depth:
            return
        if url in self._visited:
            return
        if not self._is_allowed(url):
            return

        self._visited.add(url)

        try:
            response = self.http_client.get(url)
        except Exception as exc:
            logger.warning("Failed to fetch %s: %s", url, exc)
            return

        if response.status_code != 200:
            logger.debug("Non-200 status for %s: %d", url, response.status_code)
            return

        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            return

        self._result.pages_found.append(url)
        html = response.text

        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception as exc:
            logger.warning("Failed to parse HTML for %s: %s", url, exc)
            return

        internal_links: List[str] = []

        # --- Extract <a href> ---
        for tag in soup.find_all("a", href=True):
            link = self._normalize_url(url, tag["href"])
            if self._is_allowed(link):
                internal_links.append(link)
            else:
                if link not in self._result.external_links:
                    self._result.external_links.append(link)

        # --- Extract <script src> ---
        for tag in soup.find_all("script", src=True):
            src = self._normalize_url(url, tag["src"])
            if src not in self._result.scripts_found:
                self._result.scripts_found.append(src)

        # --- Extract <img src> ---
        for tag in soup.find_all("img", src=True):
            src = self._normalize_url(url, tag["src"])
            if src not in self._result.images_found:
                self._result.images_found.append(src)

        # --- Extract <iframe src> ---
        for tag in soup.find_all("iframe", src=True):
            src = self._normalize_url(url, tag["src"])
            if self._is_allowed(src):
                internal_links.append(src)
            else:
                if src not in self._result.external_links:
                    self._result.external_links.append(src)

        # --- Extract <form> ---
        self._extract_forms(soup, url)

        # --- Follow internal links recursively ---
        for link in internal_links:
            self._crawl_page(link, depth + 1)

    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> None:
        """Parse all ``<form>`` elements on the page."""
        for form_tag in soup.find_all("form"):
            action_raw = form_tag.get("action", "")
            action_url = self._normalize_url(page_url, action_raw) if action_raw else page_url
            method = (form_tag.get("method") or "GET").upper()

            inputs: List[Dict[str, Optional[str]]] = []
            for inp in form_tag.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "name": inp.get("name"),
                    "type": inp.get("type", "text"),
                    "required": "required" if inp.has_attr("required") else None,
                })

            form_info = FormInfo(
                action_url=action_url,
                method=method,
                page_url=page_url,
                inputs=inputs,
            )
            self._result.forms_found.append(form_info)
