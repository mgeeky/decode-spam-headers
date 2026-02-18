from __future__ import annotations

from fastapi import APIRouter

from app.engine.scanner_registry import ScannerRegistry
from app.schemas.tests import TestListResponse, TestResponse

router = APIRouter(prefix="/api", tags=["tests"])


@router.get("/tests", response_model=TestListResponse)
def list_tests() -> TestListResponse:
    registry = ScannerRegistry()
    tests = registry.list_tests()
    response_tests = [TestResponse.model_validate(test.model_dump()) for test in tests]
    return TestListResponse(tests=response_tests, total_count=len(response_tests))
