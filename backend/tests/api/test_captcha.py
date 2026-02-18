from __future__ import annotations

import base64
import json
import time

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.config import get_settings
from app.main import app
from app.security.captcha import create_captcha_challenge, verify_bypass_token


def _assert_png_base64(image_base64: str) -> None:
    decoded = base64.b64decode(image_base64)
    assert decoded.startswith(b"\x89PNG\r\n\x1a\n")


def _decode_token_payload(token: str) -> dict:
    payload_b64 = token.split(".")[0]
    padding = "=" * (-len(payload_b64) % 4)
    payload_raw = base64.urlsafe_b64decode(payload_b64 + padding)
    return json.loads(payload_raw.decode("utf-8"))


@pytest.mark.anyio
async def test_captcha_challenge_generation_produces_image() -> None:
    challenge = create_captcha_challenge()

    assert challenge.challenge_token
    assert challenge.image_base64
    assert challenge.answer
    _assert_png_base64(challenge.image_base64)


@pytest.mark.anyio
async def test_captcha_verify_rejects_invalid_answer() -> None:
    challenge = create_captcha_challenge()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/api/captcha/verify",
            json={"challengeToken": challenge.challenge_token, "answer": "incorrect"},
        )

    assert response.status_code == 400
    payload = response.json()
    assert payload.get("error") or payload.get("detail")


@pytest.mark.anyio
async def test_captcha_verify_returns_bypass_token() -> None:
    challenge = create_captcha_challenge()
    client_ip = "203.0.113.9"

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/api/captcha/verify",
            json={"challengeToken": challenge.challenge_token, "answer": challenge.answer},
            headers={"x-forwarded-for": client_ip},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    token = payload["bypassToken"]
    assert token
    assert verify_bypass_token(token, client_ip)

    settings = get_settings()
    decoded_payload = _decode_token_payload(token)
    assert decoded_payload["ip"] == client_ip
    assert isinstance(decoded_payload.get("exp"), int)
    now = int(time.time())
    ttl_seconds = settings.captcha_bypass_ttl_seconds
    assert ttl_seconds - 10 <= decoded_payload["exp"] - now <= ttl_seconds + 10
