"""Safety mechanisms for OneSyberTest.

All guards are designed to halt the tool immediately when something
unexpected happens, preventing accidental damage to production systems.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import List, Optional

from core.logger import get_logger


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class SafetyStop(Exception):
    """Raised when a safety mechanism triggers an immediate stop."""

    def __init__(self, reason: str, *, source: str = "unknown") -> None:
        self.reason = reason
        self.source = source
        super().__init__(f"[SafetyStop:{source}] {reason}")


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------

class CircuitBreaker:
    """Tracks consecutive errors and trips after *threshold* is reached."""

    def __init__(self, threshold: int) -> None:
        self.threshold = threshold
        self._consecutive_errors: int = 0
        self._total_errors: int = 0

    def record_success(self) -> None:
        self._consecutive_errors = 0

    def record_error(self, detail: str = "") -> None:
        self._consecutive_errors += 1
        self._total_errors += 1
        if self._consecutive_errors >= self.threshold:
            raise SafetyStop(
                f"Circuit breaker tripped after {self._consecutive_errors} "
                f"consecutive errors. Last: {detail}",
                source="CircuitBreaker",
            )

    @property
    def consecutive_errors(self) -> int:
        return self._consecutive_errors

    @property
    def total_errors(self) -> int:
        return self._total_errors


# ---------------------------------------------------------------------------
# Runtime guard
# ---------------------------------------------------------------------------

class RuntimeGuard:
    """Raises :class:`SafetyStop` when elapsed time exceeds the budget."""

    def __init__(self, max_runtime_minutes: int) -> None:
        self.max_seconds: float = max_runtime_minutes * 60.0
        self._start: float = time.monotonic()

    def check(self) -> None:
        elapsed = time.monotonic() - self._start
        if elapsed >= self.max_seconds:
            mins = elapsed / 60.0
            raise SafetyStop(
                f"Runtime exceeded: {mins:.1f} min (limit {self.max_seconds / 60:.0f} min)",
                source="RuntimeGuard",
            )

    def reset(self) -> None:
        """Reset the start time to *now*.

        Useful when the runtime limit should apply only to a specific
        phase (e.g. the test phase) rather than the entire process
        lifetime.
        """
        self._start = time.monotonic()

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self._start


# ---------------------------------------------------------------------------
# Request budget
# ---------------------------------------------------------------------------

class RequestBudget:
    """Raises :class:`SafetyStop` when total requests exceed the budget."""

    def __init__(self, max_total_requests: int) -> None:
        self.max_total_requests = max_total_requests
        self._count: int = 0

    def consume(self) -> None:
        self._count += 1
        if self._count > self.max_total_requests:
            raise SafetyStop(
                f"Request budget exhausted: {self._count}/{self.max_total_requests}",
                source="RequestBudget",
            )

    @property
    def count(self) -> int:
        return self._count

    @property
    def remaining(self) -> int:
        return max(0, self.max_total_requests - self._count)


# ---------------------------------------------------------------------------
# Real data detector
# ---------------------------------------------------------------------------

@dataclass
class DetectionMatch:
    pattern_name: str
    matched_text: str
    context: str = ""


class RealDataDetector:
    """Scans text for patterns that look like real personal data.

    Detects Israeli phone numbers, real email addresses, credit-card
    numbers (Luhn-valid), and Israeli ID numbers.
    """

    # Israeli mobile/landline: 05X-XXXXXXX, 0X-XXXXXXX
    _ISRAELI_PHONE = re.compile(
        r"\b0(?:5[0-9]|[2-489])-?\d{7}\b"
    )
    # Credit-card-shaped numbers (13-19 digits, optionally separated by
    # spaces or dashes).
    _CC_RAW = re.compile(
        r"\b(?:\d[ -]?){13,19}\b"
    )
    # Israeli ID number: 9 digits (simple pattern; Luhn-like check below).
    _IL_ID = re.compile(r"\b\d{9}\b")
    # "Real-looking" emails -- we flag anything that is NOT an obvious
    # test address (test@, example.com, mailinator, etc.).
    _EMAIL = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    )
    _SAFE_EMAIL_DOMAINS = {
        "example.com", "example.org", "example.net",
        "test.com", "test.org", "mailinator.com",
        "localhost",
    }

    # Known example / placeholder phone numbers to ignore
    _EXAMPLE_PHONES = {
        "0501234567", "0521234567", "0531234567", "0541234567",
        "0551234567", "0501111111", "0500000000", "0521111111",
    }

    def scan(self, text: str, *, content_type: str = "") -> List[DetectionMatch]:
        """Return a list of matches found in *text*.

        Args:
            text: The response body to scan.
            content_type: The Content-Type header value. JavaScript, CSS, and
                similar non-data content types are skipped to avoid false
                positives from regex patterns and example values in source code.
        """
        # Skip scanning of JavaScript, CSS, and other code content
        ct_lower = content_type.lower()
        skip_types = ("javascript", "ecmascript", "css", "font", "image", "audio", "video")
        if any(t in ct_lower for t in skip_types):
            return []

        # For very large responses (>200KB) that look like bundled code, skip
        if len(text) > 200_000 and ("function" in text[:5000] and "var " in text[:5000]):
            return []

        matches: List[DetectionMatch] = []

        for m in self._ISRAELI_PHONE.finditer(text):
            phone = re.sub(r"-", "", m.group())
            if phone not in self._EXAMPLE_PHONES:
                matches.append(DetectionMatch("israeli_phone", m.group()))

        for m in self._CC_RAW.finditer(text):
            digits = re.sub(r"[- ]", "", m.group())
            if len(digits) >= 13 and self._luhn_check(digits):
                matches.append(DetectionMatch("credit_card", m.group()))

        for m in self._IL_ID.finditer(text):
            # Skip 9-digit numbers that are powers of 2 or other common
            # programmatic constants (very unlikely to be real IDs)
            num = int(m.group())
            if num < 100_000_000:  # IDs start from ~100M
                continue
            if self._il_id_check(m.group()):
                matches.append(DetectionMatch("israeli_id", m.group()))

        for m in self._EMAIL.finditer(text):
            domain = m.group().split("@", 1)[1].lower()
            local = m.group().split("@", 1)[0].lower()
            if domain not in self._SAFE_EMAIL_DOMAINS and "test" not in local:
                matches.append(DetectionMatch("real_email", m.group()))

        return matches

    @staticmethod
    def _luhn_check(number: str) -> bool:
        digits = [int(d) for d in number]
        checksum = 0
        reverse = digits[::-1]
        for i, d in enumerate(reverse):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        return checksum % 10 == 0

    @staticmethod
    def _il_id_check(number: str) -> bool:
        """Validate an Israeli ID number using the official check-digit algorithm."""
        if len(number) != 9:
            return False
        total = 0
        for i, ch in enumerate(number):
            d = int(ch) * ((i % 2) + 1)
            if d > 9:
                d -= 9
            total += d
        return total % 10 == 0


# ---------------------------------------------------------------------------
# Safety manager (aggregator)
# ---------------------------------------------------------------------------

class SafetyManager:
    """Combines all safety guards into a single facade.

    Call :meth:`pre_request` before each HTTP request and
    :meth:`post_request` after to run all applicable checks.
    """

    def __init__(
        self,
        *,
        max_consecutive_errors: int = 10,
        max_runtime_minutes: int = 60,
        max_total_requests: int = 5000,
    ) -> None:
        self.circuit_breaker = CircuitBreaker(max_consecutive_errors)
        self.runtime_guard = RuntimeGuard(max_runtime_minutes)
        self.request_budget = RequestBudget(max_total_requests)
        self.data_detector = RealDataDetector()
        self._logger = get_logger("onesyber.safety")

    # -- hooks called around each request --------------------------------

    def pre_request(self) -> None:
        """Run guards that should be checked *before* sending a request."""
        self.runtime_guard.check()
        self.request_budget.consume()

    def post_request(self, *, success: bool, response_text: str = "", content_type: str = "", detail: str = "") -> None:
        """Run guards that should be checked *after* receiving a response.

        Args:
            success: Whether the HTTP request succeeded (2xx/3xx).
            response_text: The response body to scan for real data.
            content_type: The Content-Type header for context-aware scanning.
            detail: Optional error description for the circuit breaker.
        """
        if success:
            self.circuit_breaker.record_success()
        else:
            self.circuit_breaker.record_error(detail)

        if response_text:
            detections = self.data_detector.scan(response_text, content_type=content_type)
            if detections:
                summary = "; ".join(
                    f"{d.pattern_name}: {d.matched_text}" for d in detections[:5]
                )
                self._logger.critical(
                    "Real personal data detected in response: %s", summary
                )
                raise SafetyStop(
                    f"Real personal data detected in response: {summary}",
                    source="RealDataDetector",
                )

    # -- convenience properties ------------------------------------------

    @property
    def stats(self) -> dict:
        return {
            "requests_sent": self.request_budget.count,
            "requests_remaining": self.request_budget.remaining,
            "consecutive_errors": self.circuit_breaker.consecutive_errors,
            "total_errors": self.circuit_breaker.total_errors,
            "elapsed_seconds": self.runtime_guard.elapsed_seconds,
        }
