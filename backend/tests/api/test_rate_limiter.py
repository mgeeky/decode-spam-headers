from __future__ import annotations

import importlib
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app.core import config as config_module
from app.security.captcha import BYPASS_TOKEN_HEADER, issue_bypass_token

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"


def _load_app(
    monkeypatch: pytest.MonkeyPatch,
    *,
    limit: int = 2,
    window_seconds: int = 60,
):
    monkeypatch.setenv("WHA_RATE_LIMIT_REQUESTS", str(limit))
    monkeypatch.setenv("WHA_RATE_LIMIT_WINDOW_SECONDS", str(window_seconds))
    config_module.get_settings.cache_clear()

    import app.main as main

    importlib.reload(main)
    return main.app


@pytest.mark.anyio
async def test_rate_limiter_returns_captcha_challenge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _load_app(monkeypatch)
    raw_headers = (FIXTURES_DIR / "sample_headers.txt").read_text(encoding="utf-8")
    request_payload = {
        "headers": raw_headers,
        "config": {"testIds": [], "resolve": False, "decodeAll": False},
    }

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        for _ in range(2):
            response = await client.post("/api/analyse", json=request_payload)
            assert response.status_code == 200

        response = await client.post("/api/analyse", json=request_payload)

    assert response.status_code == 429
    assert "Retry-After" in response.headers

    retry_after_header = int(response.headers["Retry-After"])
    payload = response.json()
    assert payload["retryAfter"] == retry_after_header
    assert "captchaChallenge" in payload

    challenge = payload["captchaChallenge"]
    assert challenge["challengeToken"]
    assert challenge["imageBase64"]


@pytest.mark.anyio
async def test_rate_limiter_allows_bypass_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _load_app(monkeypatch, limit=1, window_seconds=60)
    raw_headers = (FIXTURES_DIR / "sample_headers.txt").read_text(encoding="utf-8")
    request_payload = {
        "headers": raw_headers,
        "config": {"testIds": [], "resolve": False, "decodeAll": False},
    }
    client_ip = "203.0.113.5"
    bypass_token = issue_bypass_token(client_ip)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/api/analyse",
            json=request_payload,
            headers={"x-forwarded-for": client_ip},
        )
        assert response.status_code == 200

        response = await client.post(
            "/api/analyse",
            json=request_payload,
            headers={"x-forwarded-for": client_ip},
        )
        assert response.status_code == 429

        response = await client.post(
            "/api/analyse",
            json=request_payload,
            headers={
                "x-forwarded-for": client_ip,
                BYPASS_TOKEN_HEADER: bypass_token,
            },
        )

    assert response.status_code == 200
