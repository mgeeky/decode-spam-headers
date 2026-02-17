from __future__ import annotations

from ._legacy_adapter import build_scanners


SCANNERS = build_scanners(
    [27, 28, 29, 38, 39, 40, 41, 42, 43, 88, 89],
    category="IronPort",
)
