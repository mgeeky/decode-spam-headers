from __future__ import annotations

from fastapi import APIRouter

from app.engine.scanner_registry import ScannerRegistry
from app.schemas.tests import TestResponse

router = APIRouter(prefix="/api", tags=["tests"])


@router.get("/tests", response_model=list[TestResponse])
def list_tests() -> list[TestResponse]:
    registry = ScannerRegistry()
    tests = registry.list_tests()
    return [TestResponse.model_validate(test) for test in tests]
