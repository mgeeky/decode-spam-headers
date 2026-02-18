from __future__ import annotations

import os
import time
import tomllib
from importlib import metadata
from pathlib import Path

from fastapi import APIRouter

from app.engine.scanner_registry import ScannerRegistry
from app.schemas.health import HealthResponse

router = APIRouter(prefix="/api", tags=["health"])

_START_TIME = time.monotonic()
_PROJECT_NAME = "web-header-analyzer-backend"


@router.get("/health", response_model=HealthResponse)
def health_check() -> HealthResponse:
    status = "up"
    scanner_count = 0

    try:
        registry = ScannerRegistry()
        scanner_count = len(registry.list_tests())
        if scanner_count == 0:
            status = "degraded"
    except Exception:
        status = "down"
        scanner_count = 0

    return HealthResponse(
        status=status,
        version=_resolve_version(),
        uptime=_uptime_seconds(),
        scanner_count=scanner_count,
    )


def _uptime_seconds() -> float:
    return max(0.0, time.monotonic() - _START_TIME)


def _resolve_version() -> str:
    env_version = os.getenv("WHA_VERSION", "").strip()
    if env_version:
        return env_version

    try:
        return metadata.version(_PROJECT_NAME)
    except metadata.PackageNotFoundError:
        pass

    pyproject_path = Path(__file__).resolve().parents[2] / "pyproject.toml"
    if pyproject_path.exists():
        try:
            data = pyproject_path.read_text(encoding="utf-8")
        except OSError:
            data = ""
        if data:
            try:
                parsed = tomllib.loads(data)
            except ValueError:
                parsed = {}
            version = (
                parsed.get("project", {}).get("version")
                if isinstance(parsed, dict)
                else None
            )
            if isinstance(version, str) and version.strip():
                return version.strip()

    return "unknown"
