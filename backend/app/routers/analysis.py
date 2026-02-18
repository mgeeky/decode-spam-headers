from __future__ import annotations

import json
from time import perf_counter
from typing import Any

import anyio
from anyio import BrokenResourceError, ClosedResourceError
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import ValidationError

from app.core.config import get_settings
from app.engine.analyzer import HeaderAnalyzer
from app.engine.models import AnalysisResult, ReportMetadata
from app.engine.scanner_registry import ScannerRegistry
from app.schemas.analysis import AnalysisProgress, AnalysisRequest

MAX_HEADERS_LENGTH = 1_048_576

router = APIRouter(prefix="/api", tags=["analysis"])


def _sanitize_headers(value: str) -> str:
    if not value:
        return value
    cleaned = value.replace("\x00", "")
    cleaned = "".join(
        ch for ch in cleaned if ch in ("\n", "\r", "\t") or ch.isprintable()
    )
    return cleaned


def _format_sse(event: str, data: object) -> str:
    payload = json.dumps(data)
    return f"event: {event}\ndata: {payload}\n\n"


def _build_timeout_result(
    expected_tests: list[str],
    last_index: int | None,
    elapsed_ms: float,
) -> AnalysisResult:
    total_tests = len(expected_tests)
    if last_index is None:
        incomplete = list(expected_tests)
    else:
        incomplete = expected_tests[last_index:]

    metadata = ReportMetadata(
        total_tests=total_tests,
        passed_tests=0,
        failed_tests=0,
        skipped_tests=0,
        elapsed_ms=elapsed_ms,
        timed_out=True,
        incomplete_tests=incomplete,
    )
    return AnalysisResult(results=[], metadata=metadata)


@router.post("/analyse")
async def analyse(request: Request) -> StreamingResponse:
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid request payload")

    headers = payload.get("headers")
    if not isinstance(headers, str):
        raise HTTPException(status_code=400, detail="Headers must be a string")

    if not headers.strip():
        return JSONResponse(
            status_code=400, content={"error": "Headers cannot be empty"}
        )

    if len(headers) > MAX_HEADERS_LENGTH:
        return JSONResponse(status_code=413, content={"error": "Headers exceed 1 MB"})

    headers = _sanitize_headers(headers)
    if not headers.strip():
        return JSONResponse(
            status_code=400, content={"error": "Headers cannot be empty"}
        )

    config = payload.get("config") or {}
    try:
        analysis_request = AnalysisRequest.model_validate(
            {"headers": headers, "config": config}
        )
    except ValidationError as exc:
        return JSONResponse(
            status_code=400,
            content={"error": "Invalid analysis request", "detail": exc.errors()},
        )

    settings = get_settings()
    analyzer = HeaderAnalyzer()
    registry = ScannerRegistry()
    if analysis_request.config.test_ids:
        scanners = registry.get_by_ids(analysis_request.config.test_ids)
    else:
        scanners = registry.get_all()
    expected_tests = [scanner.name for scanner in scanners]

    start = perf_counter()
    progress_state: dict[str, Any] = {"last_index": None}
    send_stream, receive_stream = anyio.create_memory_object_stream[
        tuple[str, dict[str, Any]]
    ](max_buffer_size=0)

    def on_progress(current_index: int, total_tests: int, test_name: str) -> None:
        progress_state["last_index"] = current_index
        elapsed_ms = (perf_counter() - start) * 1000
        percentage = 0.0
        if total_tests > 0:
            percentage = min(100.0, (current_index + 1) / total_tests * 100.0)
        payload = AnalysisProgress(
            current_index=current_index,
            total_tests=total_tests,
            current_test=test_name,
            elapsed_ms=elapsed_ms,
            percentage=percentage,
        ).model_dump(by_alias=True)
        try:
            anyio.from_thread.run(send_stream.send, ("progress", payload))
        except (BrokenResourceError, ClosedResourceError, RuntimeError):
            pass

    async def run_analysis() -> None:
        result: AnalysisResult | None = None
        timed_out = False
        async with send_stream:
            try:
                with anyio.fail_after(settings.analysis_timeout_seconds):
                    result = await anyio.to_thread.run_sync(
                        analyzer.analyze, analysis_request, on_progress
                    )
            except TimeoutError:
                timed_out = True

            elapsed_ms = (perf_counter() - start) * 1000
            if timed_out:
                final_result = _build_timeout_result(
                    expected_tests,
                    progress_state["last_index"],
                    elapsed_ms,
                )
            else:
                final_result = result or AnalysisResult(
                    results=[],
                    metadata=ReportMetadata(
                        total_tests=len(expected_tests),
                        passed_tests=0,
                        failed_tests=0,
                        skipped_tests=0,
                        elapsed_ms=elapsed_ms,
                        timed_out=False,
                        incomplete_tests=[],
                    ),
                )

            await send_stream.send(("result", final_result.model_dump(by_alias=True)))
            await send_stream.send(("done", {}))

    async def event_stream() -> Any:
        async with anyio.create_task_group() as task_group:
            task_group.start_soon(run_analysis)
            async with receive_stream:
                async for event_type, data in receive_stream:
                    if event_type == "done":
                        break
                    yield _format_sse(event_type, data)
            task_group.cancel_scope.cancel()

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache"},
    )
