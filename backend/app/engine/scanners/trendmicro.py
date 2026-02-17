from __future__ import annotations

from ._legacy_adapter import build_scanners

SCANNERS = build_scanners(list(range(47, 60)) + [97], category="Trend Micro")
