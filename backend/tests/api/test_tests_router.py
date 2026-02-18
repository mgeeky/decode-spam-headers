from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.engine.scanner_registry import ScannerRegistry
from app.main import app


@pytest.mark.anyio
async def test_get_tests_returns_all_registered_tests() -> None:
    registry = ScannerRegistry()
    expected = registry.list_tests()
    expected_lookup = {test.id: test.name for test in expected}

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get("/api/tests")

    assert response.status_code == 200

    payload = response.json()
    assert isinstance(payload, list)
    assert len(payload) == len(expected_lookup)

    response_lookup = {item["id"]: item["name"] for item in payload}
    assert len(response_lookup) == len(expected_lookup)
    assert response_lookup == expected_lookup
