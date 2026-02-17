from __future__ import annotations

from pathlib import Path

from app.engine.analyzer import HeaderAnalyzer
from app.engine.models import AnalysisRequest, AnalysisResult, TestResult


FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"


def test_analyzer_runs_selected_tests_and_reports_progress() -> None:
    raw_headers = (FIXTURES_DIR / "sample_headers.txt").read_text(encoding="utf-8")
    request = AnalysisRequest(
        headers=raw_headers,
        config={
            "test_ids": [12, 13],
            "resolve": False,
            "decode_all": False,
        },
    )

    progress_events: list[tuple[int, int, str]] = []

    def on_progress(current_index: int, total_tests: int, test_name: str) -> None:
        progress_events.append((current_index, total_tests, test_name))

    analyzer = HeaderAnalyzer()
    result = analyzer.analyze(request, progress_callback=on_progress)

    assert isinstance(result, AnalysisResult)
    assert len(result.results) == 2
    assert [item.test_id for item in result.results] == [12, 13]
    assert all(isinstance(item, TestResult) for item in result.results)

    assert result.metadata.total_tests == 2
    assert (
        result.metadata.passed_tests
        + result.metadata.failed_tests
        + result.metadata.skipped_tests
    ) == result.metadata.total_tests

    assert progress_events
    assert all(total == 2 for _, total, _ in progress_events)
    assert progress_events[0][0] == 0
    assert progress_events[-1][0] == 1