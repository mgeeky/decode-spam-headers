from __future__ import annotations

from ._legacy_adapter import build_scanners

SCANNERS = build_scanners(
    [31, 32, 33, 34, 35, 80, 83, 84, 85, 99, 100, 101, 102],
    category="Microsoft",
)
