from __future__ import annotations

from app.engine.scanner_registry import ScannerRegistry


def test_registry_discovers_all_scanners() -> None:
    registry = ScannerRegistry()
    scanners = registry.get_all()

    assert len(scanners) >= 106

    ids = [scanner.id for scanner in scanners]
    assert len(ids) == len(set(ids))
    assert {1, 12, 66}.issubset(set(ids))


def test_registry_filters_by_ids_and_lists_tests() -> None:
    registry = ScannerRegistry()
    selected = registry.get_by_ids([1, 12, 66])

    assert [scanner.id for scanner in selected] == [1, 12, 66]

    tests = registry.list_tests()
    lookup = {test.id: test for test in tests}

    assert lookup[1].name == "Received - Mail Servers Flow"
    assert lookup[12].name == "X-Forefront-Antispam-Report"
    assert lookup[66].name == "X-Proofpoint-Spam-Details"

    assert lookup[1].category
    assert lookup[12].category
    assert lookup[66].category
