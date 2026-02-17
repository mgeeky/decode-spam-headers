from __future__ import annotations

from ._legacy_adapter import build_scanners


SCANNERS = build_scanners([1, 2, 3], category="Received Headers")
