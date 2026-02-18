from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from app.schemas.captcha import CaptchaVerifyRequest, CaptchaVerifyResponse
from app.security.captcha import issue_bypass_token, verify_captcha_answer

router = APIRouter(prefix="/api", tags=["security"])


@router.post("/captcha/verify", response_model=CaptchaVerifyResponse)
async def verify_captcha(
    payload: CaptchaVerifyRequest, request: Request
) -> CaptchaVerifyResponse:
    client_ip = _get_client_ip(request)
    if not verify_captcha_answer(payload.challenge_token, payload.answer):
        raise HTTPException(status_code=400, detail="Invalid captcha response")

    bypass_token = issue_bypass_token(client_ip)
    return CaptchaVerifyResponse(success=True, bypass_token=bypass_token)


def _get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip() or "unknown"
    if request.client and request.client.host:
        return request.client.host
    return "unknown"
