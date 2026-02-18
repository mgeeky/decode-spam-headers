from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from app.engine.models import (
    AnalysisConfig,
)
from app.engine.models import (
    AnalysisRequest as EngineAnalysisRequest,
)
from app.engine.models import (
    AnalysisResult as EngineAnalysisResult,
)


class AnalysisRequest(EngineAnalysisRequest):
    pass


class AnalysisProgress(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    current_index: int = Field(alias="currentIndex")
    total_tests: int = Field(alias="totalTests")
    current_test: str = Field(alias="currentTest")
    elapsed_ms: float = Field(alias="elapsedMs")
    percentage: float


class AnalysisReport(EngineAnalysisResult):
    pass


__all__ = [
    "AnalysisConfig",
    "AnalysisProgress",
    "AnalysisReport",
    "AnalysisRequest",
]
