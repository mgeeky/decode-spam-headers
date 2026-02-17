from __future__ import annotations

from ._legacy_adapter import build_scanners


SCANNERS = build_scanners(
    [12, 13, 14, 15, 16, 63, 64],
    category="Forefront Antispam",
)
