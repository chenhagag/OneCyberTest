"""Logging setup for OneSyberTest.

Provides file and coloured console logging with automatic censoring of
sensitive data (passwords, tokens, etc.).
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from colorama import Fore, Style, init as colorama_init

# Initialise colorama for Windows ANSI support.
colorama_init(autoreset=True)

# ---------------------------------------------------------------------------
# Sensitive-data censoring
# ---------------------------------------------------------------------------

_SENSITIVE_KEYS: List[str] = [
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "cookie",
]

# Patterns: key=value, "key": "value", key: value
_CENSOR_PATTERNS = [
    re.compile(
        rf'(["\']?(?:{"|".join(_SENSITIVE_KEYS)})["\']?\s*[:=]\s*)["\']?[^"\'&\s,\}}]+["\']?',
        re.IGNORECASE,
    ),
]


def censor(text: str) -> str:
    """Replace sensitive values in *text* with ``****``."""
    result = text
    for pattern in _CENSOR_PATTERNS:
        result = pattern.sub(r"\g<1>****", result)
    return result


# ---------------------------------------------------------------------------
# Custom formatter
# ---------------------------------------------------------------------------

class _CensorFormatter(logging.Formatter):
    """Formatter that censors sensitive data before emitting the record."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        original = super().format(record)
        return censor(original)


class _ColorConsoleFormatter(_CensorFormatter):
    """Console formatter that adds colorama colours per log level."""

    _LEVEL_COLOURS = {
        logging.DEBUG: Fore.CYAN,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        colour = self._LEVEL_COLOURS.get(record.levelno, "")
        formatted = super().format(record)
        return f"{colour}{formatted}{Style.RESET_ALL}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_LOG_FORMAT = "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_configured = False


def setup_logging(
    log_dir: str | Path = "logs",
    console_level: int = logging.INFO,
    file_level: int = logging.DEBUG,
    logger_name: Optional[str] = None,
) -> logging.Logger:
    """Configure and return the application logger.

    Creates a log file in *log_dir* with a timestamp-based filename and
    attaches both a file handler (DEBUG level) and a coloured console
    handler.

    Calling this function multiple times is safe -- handlers are only
    attached once.

    Args:
        log_dir: Directory for log files (created if missing).
        console_level: Minimum level shown on the console.
        file_level: Minimum level written to the log file.
        logger_name: Logger name; defaults to ``"onesyber"``.

    Returns:
        Configured :class:`logging.Logger`.
    """
    global _configured

    name = logger_name or "onesyber"
    logger = logging.getLogger(name)

    if _configured and logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # File handler
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_handler = logging.FileHandler(
        log_path / f"onesyber_{timestamp}.log",
        encoding="utf-8",
    )
    file_handler.setLevel(file_level)
    file_handler.setFormatter(_CensorFormatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(console_level)
    console_handler.setFormatter(_ColorConsoleFormatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    _configured = True

    return logger


def get_logger(name: str = "onesyber") -> logging.Logger:
    """Return the named logger (assumes :func:`setup_logging` was called)."""
    return logging.getLogger(name)
