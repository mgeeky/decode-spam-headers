from __future__ import annotations

from ._legacy_adapter import build_scanners


SCANNERS = build_scanners([18, 19, 20, 21, 74], category="SpamAssassin")
