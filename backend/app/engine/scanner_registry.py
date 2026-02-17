from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
import inspect
import pkgutil
import re
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

from .models import Test
from .scanner_base import BaseScanner

if TYPE_CHECKING:
    from .models import TestResult
    from .parser import ParsedHeader


_CATEGORY_GROUPS: dict[str, set[int]] = {
    "Received Headers": {1, 2, 3},
    "Forefront Antispam": {12, 13, 14, 15, 16, 63, 64},
    "SpamAssassin": {18, 19, 20, 21, 74},
    "IronPort": {27, 28, 29, 38, 39, 40, 41, 42, 43, 88, 89},
    "Mimecast": {30, 61, 62, 65},
    "Trend Micro": set(range(47, 60)) | {97},
    "Barracuda": {69, 70, 71, 72, 73},
    "Proofpoint": {66, 67},
    "Microsoft": {31, 32, 33, 34, 80, 83, 84, 85, 99, 100, 101, 102},
}


@dataclass(frozen=True)
class _StubScanner:
    id: int
    name: str
    category: str

    def run(self, headers: list[ParsedHeader]) -> TestResult | None:
        return None


class ScannerRegistry:
    def __init__(self) -> None:
        discovered = _discover_scanners()
        if discovered:
            self._scanners = _dedupe_scanners(discovered)
            self._category_map = _build_category_map(scanner.id for scanner in self._scanners)
        else:
            tests = _load_tests_from_monolith()
            self._category_map = _build_category_map(test_id for test_id, _ in tests)
            self._scanners = [
                _StubScanner(test_id, name, self._category_map[test_id])
                for test_id, name in tests
            ]
        self._by_id = {scanner.id: scanner for scanner in self._scanners}

    def get_all(self) -> list[BaseScanner]:
        return list(self._scanners)

    def get_by_ids(self, ids: Iterable[int]) -> list[BaseScanner]:
        return [self._by_id[test_id] for test_id in ids if test_id in self._by_id]

    def list_tests(self) -> list[Test]:
        return [
            Test(id=scanner.id, name=scanner.name, category=self._category_for(scanner))
            for scanner in self._scanners
        ]

    def _category_for(self, scanner: BaseScanner) -> str:
        category = getattr(scanner, "category", None)
        if isinstance(category, str) and category.strip():
            return category.strip()
        return self._category_map.get(scanner.id, "General")


def _build_category_map(test_ids: Iterable[int]) -> dict[int, str]:
    mapping: dict[int, str] = {}
    for category, ids in _CATEGORY_GROUPS.items():
        for test_id in ids:
            mapping[test_id] = category
    for test_id in test_ids:
        mapping.setdefault(test_id, "General")
    return mapping


def _discover_scanners() -> list[BaseScanner]:
    try:
        package = import_module("app.engine.scanners")
    except ModuleNotFoundError:
        return []

    scanners: list[BaseScanner] = []
    for module_info in pkgutil.iter_modules(package.__path__, f"{package.__name__}."):
        module = import_module(module_info.name)
        scanners.extend(_extract_scanners(module))
    return scanners


def _extract_scanners(module: object) -> list[BaseScanner]:
    scanners: list[BaseScanner] = []
    if hasattr(module, "SCANNERS"):
        declared = getattr(module, "SCANNERS")
        if isinstance(declared, list | tuple):
            scanners.extend(declared)
    if hasattr(module, "get_scanners") and callable(getattr(module, "get_scanners")):
        declared = getattr(module, "get_scanners")()
        if isinstance(declared, list | tuple):
            scanners.extend(declared)

    for value in vars(module).values():
        if inspect.isclass(value) and _looks_like_scanner(value):
            scanners.extend(_instantiate_scanner_class(value))
        elif _looks_like_scanner(value) and not inspect.ismodule(value):
            scanners.append(value)
    return scanners


def _looks_like_scanner(candidate: object) -> bool:
    return (
        hasattr(candidate, "id")
        and hasattr(candidate, "name")
        and callable(getattr(candidate, "run", None))
    )


def _instantiate_scanner_class(scanner_class: type) -> list[BaseScanner]:
    try:
        return [scanner_class()]
    except TypeError:
        return []


def _dedupe_scanners(scanners: Iterable[BaseScanner]) -> list[BaseScanner]:
    seen: set[int] = set()
    unique: list[BaseScanner] = []
    for scanner in scanners:
        if scanner.id in seen:
            continue
        seen.add(scanner.id)
        unique.append(scanner)
    return sorted(unique, key=lambda scanner: scanner.id)


def _load_tests_from_monolith() -> list[tuple[int, str]]:
    root = Path(__file__).resolve().parents[3]
    path = root / "decode-spam-headers.py"
    if not path.exists():
        return []

    text = path.read_text(encoding="utf-8", errors="ignore")
    start = text.find("def getAllTests")
    if start == -1:
        return []
    end = text.find("def getVersion", start)
    if end == -1:
        end = len(text)
    snippet = text[start:end]
    pattern = r"\(\s*'(?P<id>\d+)'\s*,\s*'(?P<name>[^']*)'"
    matches = re.findall(pattern, snippet)

    tests: list[tuple[int, str]] = []
    seen: set[int] = set()
    for test_id, name in matches:
        try:
            test_num = int(test_id)
        except ValueError:
            continue
        if test_num in seen:
            continue
        seen.add(test_num)
        tests.append((test_num, name))
    return sorted(tests, key=lambda item: item[0])
