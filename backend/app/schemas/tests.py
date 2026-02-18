from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from app.engine.models import Test


class TestResponse(Test):
    pass


class TestListResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    tests: list[TestResponse]
    total_count: int = Field(alias="totalCount")
