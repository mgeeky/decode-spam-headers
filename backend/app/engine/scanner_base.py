from __future__ import annotations

from typing import Protocol

from .models import TestResult
from .parser import ParsedHeader


class BaseScanner(Protocol):
    id: int
    name: str

    def run(self, headers: list[ParsedHeader]) -> TestResult | None:
        """Run the scanner against parsed headers."""
