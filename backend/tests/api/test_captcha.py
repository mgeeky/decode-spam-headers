from __future__ import annotations

import base64

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.security.captcha import create_captcha_challenge


def _assert_png_base64(image_base64: str) -> None:
    decoded = base64.b64decode(image_base64)
    assert decoded.startswith(b"\x89PNG\r\n\x1a\n")


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

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/api/captcha/verify",
            json={"challengeToken": challenge.challenge_token, "answer": challenge.answer},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["bypassToken"]
