"""Configuration loader for OneSyberTest.

Loads YAML config, validates required fields, resolves credentials
from environment variables.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


class ConfigError(Exception):
    """Raised when configuration is invalid or missing required fields."""


@dataclass
class TargetConfig:
    allowed_domains: List[str]
    base_url: str


@dataclass
class AccountCredentials:
    name: str
    email: str
    password: str
    email_env: str
    password_env: str


@dataclass
class SafetyConfig:
    max_requests_per_second: int
    max_total_requests: int
    max_runtime_minutes: int
    max_consecutive_errors: int
    concurrent_requests: int
    request_timeout_seconds: int


@dataclass
class ReportConfig:
    output_dir: str
    language: str


@dataclass
class AppConfig:
    target: TargetConfig
    accounts: Dict[str, AccountCredentials]
    safety: SafetyConfig
    report: ReportConfig
    enabled_tests: List[str]
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)


_REQUIRED_SAFETY_FIELDS = [
    "max_requests_per_second",
    "max_total_requests",
    "max_runtime_minutes",
    "max_consecutive_errors",
    "concurrent_requests",
    "request_timeout_seconds",
]


def _validate_raw(raw: Dict[str, Any]) -> None:
    """Validate that all required fields exist in the raw config dict."""
    # target section
    target = raw.get("target")
    if not isinstance(target, dict):
        raise ConfigError("Missing or invalid 'target' section in config")

    if "allowed_domains" not in target or not target["allowed_domains"]:
        raise ConfigError("target.allowed_domains is required and must not be empty")

    if "base_url" not in target or not target["base_url"]:
        raise ConfigError("target.base_url is required")

    # safety section
    safety = raw.get("safety")
    if not isinstance(safety, dict):
        raise ConfigError("Missing or invalid 'safety' section in config")

    for f in _REQUIRED_SAFETY_FIELDS:
        if f not in safety:
            raise ConfigError(f"safety.{f} is required")


def _resolve_accounts(raw_accounts: Optional[Dict[str, Any]]) -> Dict[str, AccountCredentials]:
    """Resolve account credentials from environment variables."""
    if not raw_accounts:
        return {}

    accounts: Dict[str, AccountCredentials] = {}
    for name, mapping in raw_accounts.items():
        if not isinstance(mapping, dict):
            continue
        email_env = mapping.get("email_env", "")
        password_env = mapping.get("password_env", "")

        email = os.environ.get(email_env, "") if email_env else ""
        password = os.environ.get(password_env, "") if password_env else ""

        accounts[name] = AccountCredentials(
            name=name,
            email=email,
            password=password,
            email_env=email_env,
            password_env=password_env,
        )
    return accounts


def load_config(path: str | Path) -> AppConfig:
    """Load and validate a YAML configuration file.

    Args:
        path: File-system path to the YAML config.

    Returns:
        A fully-populated ``AppConfig`` instance.

    Raises:
        ConfigError: If the file is missing, unreadable, or fails validation.
    """
    config_path = Path(path)
    if not config_path.is_file():
        raise ConfigError(f"Config file not found: {config_path}")

    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            raw: Dict[str, Any] = yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Failed to parse YAML: {exc}") from exc

    _validate_raw(raw)

    target_raw = raw["target"]
    safety_raw = raw["safety"]
    report_raw = raw.get("report", {})

    target = TargetConfig(
        allowed_domains=[d.strip() for d in target_raw["allowed_domains"] if d],
        base_url=target_raw["base_url"].rstrip("/"),
    )

    safety = SafetyConfig(
        max_requests_per_second=int(safety_raw["max_requests_per_second"]),
        max_total_requests=int(safety_raw["max_total_requests"]),
        max_runtime_minutes=int(safety_raw["max_runtime_minutes"]),
        max_consecutive_errors=int(safety_raw["max_consecutive_errors"]),
        concurrent_requests=int(safety_raw["concurrent_requests"]),
        request_timeout_seconds=int(safety_raw["request_timeout_seconds"]),
    )

    report = ReportConfig(
        output_dir=report_raw.get("output_dir", "./reports"),
        language=report_raw.get("language", "he"),
    )

    accounts = _resolve_accounts(raw.get("accounts"))

    enabled_tests: List[str] = raw.get("enabled_tests", []) or []

    return AppConfig(
        target=target,
        accounts=accounts,
        safety=safety,
        report=report,
        enabled_tests=enabled_tests,
        raw=raw,
    )
