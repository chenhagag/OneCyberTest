"""Secure HTTP client for OneSyberTest.

Every outgoing request is checked against the domain allowlist and
metered by the rate limiter and request-budget guard.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from core.config import AppConfig
from core.logger import censor, get_logger
from core.safety import SafetyManager, SafetyStop


# ---------------------------------------------------------------------------
# Response wrapper
# ---------------------------------------------------------------------------

@dataclass
class Response:
    """Thin wrapper around the data we care about from an HTTP response."""

    status_code: int
    headers: Dict[str, str]
    text: str
    elapsed_seconds: float
    url: str

    def json(self) -> Any:
        """Parse the response body as JSON."""
        import json as _json
        return _json.loads(self.text)

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400

    def __repr__(self) -> str:
        return (
            f"Response(status={self.status_code}, "
            f"size={len(self.text)}, "
            f"elapsed={self.elapsed_seconds:.3f}s)"
        )


# ---------------------------------------------------------------------------
# Domain-allowlist helpers
# ---------------------------------------------------------------------------

class DomainNotAllowed(SafetyStop):
    """Raised when a request targets a domain not in the allowlist."""

    def __init__(self, domain: str, url: str) -> None:
        super().__init__(
            f"Domain '{domain}' is not in the allowlist. Blocked URL: {url}",
            source="DomainAllowlist",
        )


def _extract_domain(url: str) -> str:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    return hostname.lower()


# ---------------------------------------------------------------------------
# Secure HTTP client
# ---------------------------------------------------------------------------

class SecureHTTPClient:
    """HTTP client with allowlist enforcement, rate limiting, and logging.

    Usage::

        client = SecureHTTPClient(config)
        resp = client.get("/api/users/me")
    """

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._allowed_domains: List[str] = [
            d.lower() for d in config.target.allowed_domains
        ]
        self._base_url: str = config.target.base_url
        self._timeout: int = config.safety.request_timeout_seconds
        self._min_interval: float = (
            1.0 / config.safety.max_requests_per_second
            if config.safety.max_requests_per_second > 0
            else 0.0
        )
        self._last_request_time: float = 0.0
        self._request_count: int = 0

        self._session = requests.Session()
        # Disable automatic redirect following so we can inspect each hop.
        self._session.max_redirects = 0

        self._safety = SafetyManager(
            max_consecutive_errors=config.safety.max_consecutive_errors,
            max_runtime_minutes=config.safety.max_runtime_minutes,
            max_total_requests=config.safety.max_total_requests,
        )
        self._logger = get_logger("onesyber.http")

        # Per-URL timeout tracking: skip a URL after 3 timeouts instead
        # of letting it trip the global circuit breaker.
        self._url_timeout_counts: Dict[str, int] = defaultdict(int)
        self._url_timeout_threshold: int = 3

    # -- public convenience methods ------------------------------------

    def get(self, url: str, **kwargs: Any) -> Response:
        return self._request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Response:
        return self._request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> Response:
        return self._request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> Response:
        return self._request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> Response:
        return self._request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> Response:
        return self._request("OPTIONS", url, **kwargs)

    # -- session helpers -----------------------------------------------

    def set_auth_token(self, token: str, *, scheme: str = "Bearer") -> None:
        """Set an ``Authorization`` header on the underlying session."""
        self._session.headers["Authorization"] = f"{scheme} {token}"
        self._logger.debug("Auth token set (scheme=%s)", scheme)

    def set_cookie(self, name: str, value: str, *, domain: str = "") -> None:
        """Add a cookie to the underlying session."""
        self._session.cookies.set(name, value, domain=domain or None)
        self._logger.debug("Cookie set: %s", name)

    def clear_auth(self) -> None:
        """Remove authentication headers and cookies."""
        self._session.headers.pop("Authorization", None)
        self._session.cookies.clear()
        self._logger.debug("Auth cleared")

    # -- properties ----------------------------------------------------

    @property
    def request_count(self) -> int:
        return self._request_count

    @property
    def safety_stats(self) -> dict:
        return self._safety.stats

    # -- internal ------------------------------------------------------

    def _resolve_url(self, url: str) -> str:
        """If *url* is a relative path, prepend the base URL."""
        if url.startswith(("http://", "https://")):
            return url
        separator = "" if url.startswith("/") else "/"
        return f"{self._base_url}{separator}{url}"

    def _check_domain(self, url: str) -> None:
        """Raise if *url*'s domain is not in the allowlist."""
        domain = _extract_domain(url)
        if domain and domain not in self._allowed_domains:
            self._logger.error("BLOCKED request to unlisted domain: %s", domain)
            raise DomainNotAllowed(domain, url)

    def _rate_limit(self) -> None:
        """Sleep if necessary to honour max_requests_per_second."""
        if self._min_interval <= 0:
            return
        now = time.monotonic()
        elapsed = now - self._last_request_time
        if elapsed < self._min_interval:
            sleep_for = self._min_interval - elapsed
            self._logger.debug("Rate limiter: sleeping %.3fs", sleep_for)
            time.sleep(sleep_for)
        self._last_request_time = time.monotonic()

    def _follow_redirects(self, resp: requests.Response, **kwargs: Any) -> requests.Response:
        """Manually follow redirects while checking each hop's domain."""
        max_hops = 10
        hops = 0
        while resp.is_redirect and hops < max_hops:
            location = resp.headers.get("Location", "")
            if not location:
                break

            # Resolve relative redirects
            if not location.startswith(("http://", "https://")):
                from urllib.parse import urljoin
                location = urljoin(resp.url, location)

            self._check_domain(location)
            self._logger.debug("Following redirect -> %s", location)

            resp = self._session.send(
                requests.Request("GET", location, headers=self._session.headers).prepare(),
                timeout=self._timeout,
                allow_redirects=False,
                **{k: v for k, v in kwargs.items() if k in ("verify", "cert", "proxies")},
            )
            hops += 1

        return resp

    def _request(self, method: str, url: str, **kwargs: Any) -> Response:
        """Central request method. All public HTTP methods delegate here."""
        full_url = self._resolve_url(url)
        self._check_domain(full_url)

        # If this URL has timed out too many times, return a synthetic
        # 408 response instead of hitting it again and risking a trip
        # of the global circuit breaker.
        if self._url_timeout_counts[full_url] >= self._url_timeout_threshold:
            self._logger.warning(
                "Skipping %s %s -- timed out %d times previously",
                method,
                full_url,
                self._url_timeout_counts[full_url],
            )
            return Response(
                status_code=408,
                headers={},
                text="Skipped: URL exceeded timeout threshold",
                elapsed_seconds=0.0,
                url=full_url,
            )

        # Safety pre-check (budget, runtime)
        self._safety.pre_request()

        # Rate-limit
        self._rate_limit()

        # Log outgoing request (censored)
        log_kwargs = {k: v for k, v in kwargs.items() if k in ("params", "data", "json")}
        self._logger.info(
            ">> %s %s %s",
            method,
            full_url,
            censor(str(log_kwargs)) if log_kwargs else "",
        )

        timeout = kwargs.pop("timeout", self._timeout)

        try:
            raw: requests.Response = self._session.request(
                method,
                full_url,
                timeout=timeout,
                allow_redirects=False,
                **kwargs,
            )

            # Follow redirects with domain checks
            raw = self._follow_redirects(raw)

            self._request_count += 1

            response = Response(
                status_code=raw.status_code,
                headers=dict(raw.headers),
                text=raw.text,
                elapsed_seconds=raw.elapsed.total_seconds(),
                url=str(raw.url),
            )

            self._logger.info(
                "<< %s %s -> %d (%d bytes, %.3fs)",
                method,
                full_url,
                response.status_code,
                len(response.text),
                response.elapsed_seconds,
            )

            success = 200 <= response.status_code < 400
            self._safety.post_request(
                success=success,
                response_text=response.text,
                content_type=response.headers.get("Content-Type", ""),
                detail=f"{response.status_code} on {method} {full_url}",
            )

            return response

        except SafetyStop:
            raise
        except requests.exceptions.Timeout as exc:
            # Track per-URL timeouts separately so one slow endpoint
            # does not trip the global circuit breaker for all URLs.
            self._request_count += 1
            self._url_timeout_counts[full_url] += 1
            self._logger.warning(
                "Timeout (%d/%d) on %s %s: %s",
                self._url_timeout_counts[full_url],
                self._url_timeout_threshold,
                method,
                full_url,
                exc,
            )
            # Do NOT call self._safety.post_request(success=False) here
            # -- timeouts are tracked per-URL, not via the global
            # circuit breaker.
            raise
        except requests.RequestException as exc:
            self._request_count += 1
            self._logger.error("Request failed: %s %s -> %s", method, full_url, exc)
            self._safety.post_request(
                success=False,
                detail=f"{type(exc).__name__}: {exc}",
            )
            raise
