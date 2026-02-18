from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from time import perf_counter
from typing import Callable

from .models import (
    AnalysisRequest,
    AnalysisResult,
    ReportMetadata,
    Severity,
    TestResult,
    TestStatus,
)
from .parser import HeaderParser, ParsedHeader
from .scanner_base import BaseScanner
from .scanner_registry import ScannerRegistry
from .scanners._legacy_adapter import configure_legacy, reset_legacy_context

ProgressCallback = Callable[[int, int, str], None]

DEFAULT_PER_TEST_TIMEOUT_SECONDS = 3.0


class HeaderAnalyzer:
    def __init__(
        self,
        parser: HeaderParser | None = None,
        registry: ScannerRegistry | None = None,
        per_test_timeout_seconds: float | None = None,
    ) -> None:
        self._parser = parser or HeaderParser()
        self._registry = registry or ScannerRegistry()
        if per_test_timeout_seconds is None:
            per_test_timeout_seconds = DEFAULT_PER_TEST_TIMEOUT_SECONDS
        self._per_test_timeout_seconds = max(0.0, float(per_test_timeout_seconds))

    def analyze(
        self,
        request: AnalysisRequest,
        progress_callback: ProgressCallback | None = None,
    ) -> AnalysisResult:
        start = perf_counter()
        reset_legacy_context()
        configure_legacy(
            resolve=request.config.resolve,
            decode_all=request.config.decode_all,
            include_unusual=True,
        )
        headers = self._parser.parse(request.headers)
        scanners = self._select_scanners(request)
        total_tests = len(scanners)

        results: list[TestResult] = []
        passed = failed = skipped = 0
        incomplete: list[str] = []

        for index, scanner in enumerate(scanners):
            if progress_callback is not None:
                try:
                    progress_callback(index, total_tests, scanner.name)
                except Exception:
                    pass

            try:
                result = self._run_scanner(scanner, headers)
            except TimeoutError as exc:
                failed += 1
                incomplete.append(scanner.name)
                results.append(self._error_result(scanner, str(exc)))
                continue
            except Exception as exc:
                failed += 1
                incomplete.append(scanner.name)
                results.append(self._error_result(scanner, str(exc)))
                continue

            if result is None:
                skipped += 1
                results.append(self._skipped_result(scanner))
                continue

            if result.status == TestStatus.error:
                failed += 1
                incomplete.append(scanner.name)
            elif result.status == TestStatus.skipped:
                skipped += 1
            else:
                passed += 1
            results.append(result)

        elapsed_ms = (perf_counter() - start) * 1000
        metadata = ReportMetadata(
            total_tests=total_tests,
            passed_tests=passed,
            failed_tests=failed,
            skipped_tests=skipped,
            elapsed_ms=elapsed_ms,
            timed_out=False,
            incomplete_tests=incomplete,
        )
        return AnalysisResult(results=results, metadata=metadata)

    def _select_scanners(self, request: AnalysisRequest) -> list[BaseScanner]:
        if request.config.test_ids:
            return self._registry.get_by_ids(request.config.test_ids)
        return self._registry.get_all()

    def _run_scanner(
        self, scanner: BaseScanner, headers: list[ParsedHeader]
    ) -> TestResult | None:
        if self._per_test_timeout_seconds <= 0:
            return scanner.run(headers)

        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(scanner.run, headers)
        try:
            return future.result(timeout=self._per_test_timeout_seconds)
        except FutureTimeoutError as exc:
            future.cancel()
            message = (
                f"Test {scanner.id} timed out after "
                f"{self._per_test_timeout_seconds:.2f}s"
            )
            raise TimeoutError(message) from exc
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    @staticmethod
    def _error_result(scanner: BaseScanner, message: str) -> TestResult:
        return TestResult(
            test_id=scanner.id,
            test_name=scanner.name,
            header_name="-",
            header_value="-",
            analysis="",
            description="",
            severity=Severity.info,
            status=TestStatus.error,
            error=message,
        )

    @staticmethod
    def _skipped_result(scanner: BaseScanner) -> TestResult:
        return TestResult(
            test_id=scanner.id,
            test_name=scanner.name,
            header_name="-",
            header_value="-",
            analysis="",
            description="",
            severity=Severity.info,
            status=TestStatus.skipped,
            error=None,
        )
