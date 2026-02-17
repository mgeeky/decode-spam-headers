from __future__ import annotations

from ._legacy_adapter import build_scanners


SCANNERS = build_scanners([66, 67], category="Proofpoint")
