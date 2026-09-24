"""OneSyberTest test modules package.

Provides the BaseTest abstract class that all penetration test modules
must inherit from.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List


class BaseTest(ABC):
    """Base class for all penetration test modules."""

    def __init__(self, http_client, config: dict, recon_data: dict):
        self.http = http_client
        self.config = config
        self.recon = recon_data
        self.results: List = []

    @abstractmethod
    def run(self) -> List:
        """Run all tests in this module. Return list of TestResult."""
        pass

    def add_result(self, **kwargs):
        """Helper to create and store a TestResult."""
        from core.reporter import TestResult

        result = TestResult(**kwargs)
        self.results.append(result)
        return result
