from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.engine.scanner_registry import ScannerRegistry
from app.main import app


@pytest.mark.anyio
async def test_health_endpoint_returns_status() -> None:
    registry = ScannerRegistry()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get("/api/health")

    assert response.status_code == 200
    payload = response.json()

    assert payload["status"] in {"up", "degraded", "down"}
    assert payload["version"]
    assert payload["uptime"] >= 0
    assert payload["scannerCount"] == len(registry.list_tests())
