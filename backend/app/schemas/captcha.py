from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class CaptchaChallenge(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    challenge_token: str = Field(alias="challengeToken")
    image_base64: str = Field(alias="imageBase64")


class CaptchaVerifyRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    challenge_token: str = Field(alias="challengeToken")
    answer: str


class CaptchaVerifyResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    success: bool
    bypass_token: str | None = Field(default=None, alias="bypassToken")


__all__ = [
    "CaptchaChallenge",
    "CaptchaVerifyRequest",
    "CaptchaVerifyResponse",
]
