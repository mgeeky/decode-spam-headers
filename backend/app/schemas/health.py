from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class HealthResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    status: Literal["up", "degraded", "down"]
    version: str
    uptime: float
    scanner_count: int = Field(alias="scannerCount")


__all__ = ["HealthResponse"]
