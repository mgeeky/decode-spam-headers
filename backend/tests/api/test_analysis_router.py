from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from app.engine.analyzer import HeaderAnalyzer
from app.engine.models import (
    AnalysisResult,
    ReportMetadata,
    Severity,
    TestResult,
    TestStatus,
)
from app.main import app

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"


def _parse_sse_events(raw: str) -> list[dict[str, Any]]:
    normalized = raw.replace("\r\n", "\n").strip()
    if not normalized:
        return []

    events: list[dict[str, Any]] = []
    for block in normalized.split("\n\n"):
        if not block.strip():
            continue
        event = "message"
        data_lines: list[str] = []
        for line in block.split("\n"):
            if not line or line.startswith(":"):
                continue
            if line.startswith("event:"):
                event = line.split(":", 1)[1].strip() or "message"
                continue
            if line.startswith("data:"):
                data_lines.append(line.split(":", 1)[1].lstrip())
        if not data_lines:
            continue
        raw_data = "\n".join(data_lines)
        try:
            data = json.loads(raw_data)
        except json.JSONDecodeError:
            data = raw_data
        events.append({"event": event, "data": data, "raw": raw_data})
    return events


async def _collect_stream_events(
    client: AsyncClient,
    payload: dict[str, Any],
) -> list[dict[str, Any]]:
    async with client.stream(
        "POST",
        "/api/analyse",
        json=payload,
        headers={"Accept": "text/event-stream"},
    ) as response:
        assert response.status_code == 200
        content_type = response.headers.get("content-type", "")
        assert content_type.startswith("text/event-stream")
        chunks: list[str] = []
        async for chunk in response.aiter_text():
            chunks.append(chunk)
    return _parse_sse_events("".join(chunks))


@pytest.mark.anyio
async def test_analyse_streams_progress_and_result() -> None:
    raw_headers = (FIXTURES_DIR / "sample_headers.txt").read_text(encoding="utf-8")
    payload = {
        "headers": raw_headers,
        "config": {"testIds": [12, 13], "resolve": False, "decodeAll": False},
    }

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        events = await _collect_stream_events(client, payload)

    progress_events = [event for event in events if event["event"] == "progress"]
    result_events = [event for event in events if event["event"] == "result"]

    assert progress_events
    assert len(result_events) == 1

    progress_payload = progress_events[0]["data"]
    assert progress_payload["currentIndex"] == 0
    assert progress_payload["totalTests"] == 2
    assert progress_payload["currentTest"]
    assert progress_payload["elapsedMs"] >= 0
    assert progress_payload["percentage"] >= 0

    result_payload = result_events[0]["data"]
    assert isinstance(result_payload["results"], list)
    assert result_payload["metadata"]["totalTests"] == 2
    assert (
        result_payload["metadata"]["passedTests"]
        + result_payload["metadata"]["failedTests"]
        + result_payload["metadata"]["skippedTests"]
    ) == 2


@pytest.mark.anyio
async def test_analyse_rejects_empty_headers() -> None:
    payload = {
        "headers": "",
        "config": {"testIds": [], "resolve": False, "decodeAll": False},
    }

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post("/api/analyse", json=payload)

    assert response.status_code == 400
    body = response.json()
    assert "error" in body or "detail" in body


@pytest.mark.anyio
async def test_analyse_rejects_oversized_headers() -> None:
    payload = {
        "headers": "a" * 1_048_577,
        "config": {"testIds": [], "resolve": False, "decodeAll": False},
    }

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post("/api/analyse", json=payload)

    assert response.status_code == 413
    body = response.json()
    assert "error" in body or "detail" in body


@pytest.mark.anyio
async def test_analyse_stream_includes_partial_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_headers = (FIXTURES_DIR / "sample_headers.txt").read_text(encoding="utf-8")

    def fake_analyze(
        self: HeaderAnalyzer,
        request: Any,
        progress_callback: Any | None = None,
    ) -> AnalysisResult:
        if progress_callback:
            progress_callback(0, 2, "Test A")
            progress_callback(1, 2, "Test B")
        return AnalysisResult(
            results=[
                TestResult(
                    test_id=12,
                    test_name="Test A",
                    header_name="X-Test",
                    header_value="value",
                    analysis="ok",
                    description="",
                    severity=Severity.clean,
                    status=TestStatus.success,
                    error=None,
                ),
                TestResult(
                    test_id=13,
                    test_name="Test B",
                    header_name="X-Test",
                    header_value="value",
                    analysis="boom",
                    description="",
                    severity=Severity.info,
                    status=TestStatus.error,
                    error="Scanner failed",
                ),
            ],
            metadata=ReportMetadata(
                total_tests=2,
                passed_tests=1,
                failed_tests=1,
                skipped_tests=0,
                elapsed_ms=5.0,
                timed_out=False,
                incomplete_tests=["Test B"],
            ),
        )

    monkeypatch.setattr(HeaderAnalyzer, "analyze", fake_analyze)

    payload = {
        "headers": raw_headers,
        "config": {"testIds": [12, 13], "resolve": False, "decodeAll": False},
    }

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        events = await _collect_stream_events(client, payload)

    result_payload = next(
        event["data"] for event in events if event["event"] == "result"
    )
    statuses = [item["status"] for item in result_payload["results"]]
    assert "error" in statuses
    error_entries = [
        item for item in result_payload["results"] if item["status"] == "error"
    ]
    assert error_entries[0]["error"]
    assert result_payload["metadata"]["failedTests"] == 1
    assert result_payload["metadata"]["incompleteTests"] == ["Test B"]


@pytest.mark.anyio
async def test_analyse_times_out_with_partial_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_headers = (FIXTURES_DIR / "sample_headers.txt").read_text(encoding="utf-8")

    def fake_analyze(
        self: HeaderAnalyzer,
        request: Any,
        progress_callback: Any | None = None,
    ) -> AnalysisResult:
        if progress_callback:
            progress_callback(0, 3, "Test A")
            progress_callback(1, 3, "Test B")
        raise TimeoutError("Analysis timed out")

    monkeypatch.setattr(HeaderAnalyzer, "analyze", fake_analyze)

    payload = {
        "headers": raw_headers,
        "config": {"testIds": [12, 13, 14], "resolve": False, "decodeAll": False},
    }

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        events = await _collect_stream_events(client, payload)

    result_payload = next(
        event["data"] for event in events if event["event"] == "result"
    )
    assert result_payload["metadata"]["timedOut"] is True
    assert result_payload["metadata"]["incompleteTests"]
