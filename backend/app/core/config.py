from __future__ import annotations

import json
from functools import lru_cache
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment variables.

    Environment variables are prefixed with `WHA_` by default.
    """

    model_config = SettingsConfigDict(env_prefix="WHA_", case_sensitive=False)

    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:3000"],
        description="Allowed CORS origins.",
    )
    rate_limit_requests: int = Field(
        default=60,
        ge=1,
        description="Max requests per window for rate limiting.",
    )
    rate_limit_window_seconds: int = Field(
        default=60,
        ge=1,
        description="Rate limit window in seconds.",
    )
    analysis_timeout_seconds: int = Field(
        default=30,
        ge=1,
        description="Hard timeout for analysis in seconds.",
    )
    debug: bool = Field(default=False, description="Enable debug mode.")

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, value: Any) -> list[str]:
        if value is None:
            return ["http://localhost:3000"]
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return []
            if text.startswith("["):
                try:
                    parsed = json.loads(text)
                    if isinstance(parsed, list):
                        return [str(item).strip() for item in parsed if str(item).strip()]
                except json.JSONDecodeError:
                    pass
            return [item.strip() for item in text.split(",") if item.strip()]
        return [str(value).strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
