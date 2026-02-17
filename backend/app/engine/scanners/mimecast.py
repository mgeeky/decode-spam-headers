from __future__ import annotations

from ._legacy_adapter import build_scanners

SCANNERS = build_scanners([30, 61, 62, 65], category="Mimecast")
