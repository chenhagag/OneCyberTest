"""Technology fingerprinting - identifies server software, frameworks, and security headers."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


@dataclass
class CookieInfo:
    """Metadata about a single cookie."""
    name: str
    httponly: bool = False
    secure: bool = False
    samesite: Optional[str] = None


@dataclass
class SecurityHeaders:
    """Presence / values of common security-related HTTP headers."""
    server: Optional[str] = None
    x_powered_by: Optional[str] = None
    x_frame_options: Optional[str] = None
    content_security_policy: Optional[str] = None
    strict_transport_security: Optional[str] = None
    x_content_type_options: Optional[str] = None
    x_xss_protection: Optional[str] = None
    referrer_policy: Optional[str] = None
    permissions_policy: Optional[str] = None
    cors_allow_origin: Optional[str] = None
    cors_allow_methods: Optional[str] = None
    cors_allow_headers: Optional[str] = None


@dataclass
class TechProfile:
    """Aggregated technology fingerprinting results."""
    security_headers: SecurityHeaders = field(default_factory=SecurityHeaders)
    cookies: List[CookieInfo] = field(default_factory=list)
    meta_tags: Dict[str, str] = field(default_factory=dict)
    js_frameworks: List[str] = field(default_factory=list)
    common_files: Dict[str, bool] = field(default_factory=dict)
    raw_headers: Dict[str, str] = field(default_factory=dict)


# Patterns used to detect JS frameworks from <script> sources or inline JS.
_FRAMEWORK_PATTERNS: List[tuple[str, re.Pattern[str]]] = [
    ("React", re.compile(r"react(?:\.min)?\.js|react-dom|__NEXT_DATA__|_next/static", re.I)),
    ("Next.js", re.compile(r"_next/|__NEXT_DATA__", re.I)),
    ("Vue.js", re.compile(r"vue(?:\.min)?\.js|vue@|__VUE__", re.I)),
    ("Nuxt.js", re.compile(r"nuxt|__NUXT__", re.I)),
    ("Angular", re.compile(r"angular(?:\.min)?\.js|ng-version|zone\.js", re.I)),
    ("jQuery", re.compile(r"jquery(?:\.min)?\.js|jquery@", re.I)),
    ("Bootstrap", re.compile(r"bootstrap(?:\.min)?\.(?:js|css)", re.I)),
    ("Tailwind CSS", re.compile(r"tailwind", re.I)),
    ("Svelte", re.compile(r"svelte", re.I)),
    ("Ember.js", re.compile(r"ember(?:\.min)?\.js", re.I)),
    ("Backbone.js", re.compile(r"backbone(?:\.min)?\.js", re.I)),
    ("Gatsby", re.compile(r"gatsby", re.I)),
    ("Remix", re.compile(r"remix|__remixContext", re.I)),
    ("Webpack", re.compile(r"webpack|webpackJsonp|__webpack_require__", re.I)),
    ("Vite", re.compile(r"/@vite/|vite/", re.I)),
]

# Common well-known file paths to probe.
_COMMON_FILES: List[str] = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/manifest.json",
    "/favicon.ico",
    "/humans.txt",
    "/crossdomain.xml",
    "/.well-known/openid-configuration",
]


class TechFingerprinter:
    """Fingerprints the technology stack of a target web application."""

    def analyze(self, http_client: Any, base_url: str) -> TechProfile:
        """Run all fingerprinting checks against *base_url*.

        Args:
            http_client: HTTP client (from core.http_client) with allowlist
                and rate-limiting enforcement.
            base_url: The root URL to fingerprint.

        Returns:
            A :class:`TechProfile` with all findings.
        """
        profile = TechProfile()

        # 1. Fetch the main page.
        try:
            response = http_client.get(base_url)
        except Exception as exc:
            logger.error("Failed to fetch %s: %s", base_url, exc)
            return profile

        # 2. Analyze response headers.
        self._analyze_headers(response, profile)

        # 3. Analyze cookies.
        self._analyze_cookies(response, profile)

        # 4. Parse HTML for meta tags and framework hints.
        content_type = response.headers.get("Content-Type", "")
        if "text/html" in content_type:
            self._analyze_html(response.text, profile)

        # 5. Probe common files.
        self._check_common_files(http_client, base_url, profile)

        logger.info(
            "Fingerprinting complete: %d frameworks detected, %d cookies, %d common files checked",
            len(profile.js_frameworks),
            len(profile.cookies),
            len(profile.common_files),
        )
        return profile

    # ------------------------------------------------------------------
    # Header analysis
    # ------------------------------------------------------------------

    def _analyze_headers(self, response: Any, profile: TechProfile) -> None:
        headers = response.headers
        profile.raw_headers = dict(headers)

        sh = profile.security_headers
        sh.server = headers.get("Server")
        sh.x_powered_by = headers.get("X-Powered-By")
        sh.x_frame_options = headers.get("X-Frame-Options")
        sh.content_security_policy = headers.get("Content-Security-Policy")
        sh.strict_transport_security = headers.get("Strict-Transport-Security")
        sh.x_content_type_options = headers.get("X-Content-Type-Options")
        sh.x_xss_protection = headers.get("X-XSS-Protection")
        sh.referrer_policy = headers.get("Referrer-Policy")
        sh.permissions_policy = headers.get("Permissions-Policy")
        sh.cors_allow_origin = headers.get("Access-Control-Allow-Origin")
        sh.cors_allow_methods = headers.get("Access-Control-Allow-Methods")
        sh.cors_allow_headers = headers.get("Access-Control-Allow-Headers")

    # ------------------------------------------------------------------
    # Cookie analysis
    # ------------------------------------------------------------------

    def _analyze_cookies(self, response: Any, profile: TechProfile) -> None:
        """Extract cookie metadata from the response.

        Works with both ``requests.Response`` (which has ``.cookies``) and
        raw ``Set-Cookie`` headers.
        """
        # Try requests-style cookies first.
        if hasattr(response, "cookies"):
            for cookie in response.cookies:
                info = CookieInfo(name=cookie.name)
                # requests cookie objects expose these via _rest or direct attrs.
                if hasattr(cookie, "has_nonstandard_attr"):
                    info.httponly = cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly")
                if hasattr(cookie, "secure"):
                    info.secure = bool(cookie.secure)
                # SameSite is tricky; parse from the raw header as fallback.
                profile.cookies.append(info)

        # Also parse raw Set-Cookie headers for SameSite and extra flags.
        set_cookie_headers: List[str] = []
        if hasattr(response.headers, "getlist"):
            set_cookie_headers = response.headers.getlist("Set-Cookie")
        else:
            # Fall back to scanning all headers for Set-Cookie.
            raw = response.headers.get("Set-Cookie")
            if raw:
                set_cookie_headers = [raw]

        for raw_cookie in set_cookie_headers:
            parts = [p.strip() for p in raw_cookie.split(";")]
            if not parts:
                continue
            name = parts[0].split("=", 1)[0].strip()
            httponly = any(p.lower() == "httponly" for p in parts)
            secure = any(p.lower() == "secure" for p in parts)
            samesite: Optional[str] = None
            for p in parts:
                if p.lower().startswith("samesite"):
                    samesite = p.split("=", 1)[-1].strip() if "=" in p else None

            # Update existing entry or add new one.
            existing = next((c for c in profile.cookies if c.name == name), None)
            if existing:
                existing.httponly = existing.httponly or httponly
                existing.secure = existing.secure or secure
                if samesite:
                    existing.samesite = samesite
            else:
                profile.cookies.append(
                    CookieInfo(name=name, httponly=httponly, secure=secure, samesite=samesite)
                )

    # ------------------------------------------------------------------
    # HTML analysis
    # ------------------------------------------------------------------

    def _analyze_html(self, html: str, profile: TechProfile) -> None:
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception as exc:
            logger.warning("HTML parse error during fingerprinting: %s", exc)
            return

        # Meta tags.
        for meta in soup.find_all("meta"):
            name = meta.get("name") or meta.get("property") or meta.get("http-equiv")
            content = meta.get("content")
            if name and content:
                profile.meta_tags[name] = content

        # Detect JS frameworks from <script> tags and full HTML.
        script_srcs = " ".join(
            tag.get("src", "") for tag in soup.find_all("script", src=True)
        )
        full_text = script_srcs + " " + html

        detected: set[str] = set()
        for framework_name, pattern in _FRAMEWORK_PATTERNS:
            if pattern.search(full_text):
                detected.add(framework_name)

        # Angular meta tag detection.
        if soup.find(attrs={"ng-version": True}):
            detected.add("Angular")

        # Generator meta tag (WordPress, Drupal, etc.).
        generator = soup.find("meta", attrs={"name": "generator"})
        if generator and generator.get("content"):
            detected.add(generator["content"])

        profile.js_frameworks = sorted(detected)

    # ------------------------------------------------------------------
    # Common files check
    # ------------------------------------------------------------------

    def _check_common_files(
        self, http_client: Any, base_url: str, profile: TechProfile
    ) -> None:
        for path in _COMMON_FILES:
            url = urljoin(base_url, path)
            try:
                resp = http_client.get(url)
                exists = resp.status_code == 200
            except Exception:
                exists = False
            profile.common_files[path] = exists
            if exists:
                logger.debug("Found common file: %s", path)
