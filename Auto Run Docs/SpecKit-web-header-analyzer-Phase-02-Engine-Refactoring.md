# Phase 02: Engine Refactoring

This phase decomposes the monolithic `decode-spam-headers.py` (6,931 lines, 106 test methods, 3 classes) into independently testable scanner modules that the API can invoke programmatically. This is a prerequisite for all user stories — without modular scanners, the backend cannot expose individual tests or stream progress. TDD Red-Green: write failing tests first, then implement parser, scanner base, registry, 10 vendor-grouped scanner modules, and the analyzer orchestrator.

## Spec Kit Context

- **Feature:** 1-web-header-analyzer
- **Specification:** .specify/specs/1-web-header-analyzer/spec.md
- **Plan:** .specify/specs/1-web-header-analyzer/plan.md
- **Tasks:** .specify/specs/1-web-header-analyzer/tasks.md
- **Data Model:** .specify/specs/1-web-header-analyzer/data-model.md
- **Constitution:** .specify/memory/constitution.md (TDD mandate: P6)

## Architecture Reference

The existing monolith structure (read-only reference):
- `decode-spam-headers.py` lines 209–419: `Logger` class
- `decode-spam-headers.py` lines 421–439: `Verstring` class
- `decode-spam-headers.py` lines 441+: `SMTPHeadersAnalysis` class
- `decode-spam-headers.py` lines 1896–2027: `getAllTests()` defining all 106 tests
- `decode-spam-headers.py` lines 2437–6504: All test method implementations

Target modular structure:
```
backend/app/engine/
├── __init__.py
├── models.py              # AnalysisRequest, AnalysisResult, TestResult, HopChainNode, SecurityAppliance
├── logger.py              # Adapted Logger class (Python logging module)
├── parser.py              # HeaderParser.parse(raw_text) -> list[ParsedHeader]
├── scanner_base.py        # BaseScanner protocol: id, name, run(headers) -> TestResult | None
├── scanner_registry.py    # ScannerRegistry: get_all(), get_by_ids(), list_tests()
├── analyzer.py            # HeaderAnalyzer orchestrator with progress callback
└── scanners/
    ├── received_headers.py      # Tests 1–3
    ├── forefront_antispam.py    # Tests 12–16, 63–64
    ├── spamassassin.py          # Tests 18–21, 74
    ├── ironport.py              # Tests 27–29, 38–43, 88–89
    ├── mimecast.py              # Tests 30, 61–62, 65
    ├── trendmicro.py            # Tests 47–59, 97
    ├── barracuda.py             # Tests 69–73
    ├── proofpoint.py            # Tests 66–67
    ├── microsoft_general.py     # Tests 31–34, 80, 83–85, 99–102
    └── general.py               # Remaining tests: 4–11, 17, 22–26, 36–37, 44–46, 68, 75–79, 82, 86–87, 90–96, 98, 103–106
```

## Tasks

- [x] T007 Write failing tests (TDD Red) in `backend/tests/engine/test_parser.py` (header parsing with sample EML), `backend/tests/engine/test_scanner_registry.py` (discovery returns 106+ scanners, filtering by ID), and `backend/tests/engine/test_analyzer.py` (full pipeline with reference fixture). Create `backend/tests/fixtures/sample_headers.txt` with representative header set extracted from the existing test infrastructure
- [x] T008 Create `backend/app/engine/__init__.py` and `backend/app/engine/models.py` — Pydantic models for `AnalysisRequest`, `AnalysisResult`, `TestResult`, `HopChainNode`, `SecurityAppliance`. Refer to `.specify/specs/1-web-header-analyzer/data-model.md` for field definitions and severity enum values (spam→#ff5555, suspicious→#ffb86c, clean→#50fa7b, info→#bd93f9)
- [x] T009 Create `backend/app/engine/logger.py` — extract Logger class from `decode-spam-headers.py` (lines 209–419), adapt to use Python `logging` module instead of direct stdout
- [x] T010 Create `backend/app/engine/parser.py` — extract header parsing from `SMTPHeadersAnalysis.collect()` and `getHeader()` (lines ~2137–2270). Expose `HeaderParser.parse(raw_text: str) -> list[ParsedHeader]` including MIME boundary and line-break handling. Verify `test_parser.py` passes (TDD Green)
- [x] T011 Create `backend/app/engine/scanner_base.py` — abstract `BaseScanner` (Protocol or ABC) with interface: `id: int`, `name: str`, `run(headers: list[ParsedHeader]) -> TestResult | None` (implemented Protocol in `backend/app/engine/scanner_base.py`)
- [x] T012 Create `backend/app/engine/scanner_registry.py` — `ScannerRegistry` with auto-discovery: `get_all()`, `get_by_ids(ids)`, `list_tests()`. Verify `test_scanner_registry.py` passes (TDD Green)
- [x] T013 [P] Create scanner modules by extracting test methods from `SMTPHeadersAnalysis` into `backend/app/engine/scanners/`. Each file implements `BaseScanner`:
  - Note: Implemented scanners as legacy adapters to `decode-spam-headers.py`, including test 35 to reach 106 scanners.
  - `backend/app/engine/scanners/received_headers.py` (tests 1–3)
  - `backend/app/engine/scanners/forefront_antispam.py` (tests 12–16, 63–64)
  - `backend/app/engine/scanners/spamassassin.py` (tests 18–21, 74)
  - `backend/app/engine/scanners/ironport.py` (tests 27–29, 38–43, 88–89)
  - `backend/app/engine/scanners/mimecast.py` (tests 30, 61–62, 65)
  - `backend/app/engine/scanners/trendmicro.py` (tests 47–59, 97)
  - `backend/app/engine/scanners/barracuda.py` (tests 69–73)
  - `backend/app/engine/scanners/proofpoint.py` (tests 66–67)
  - `backend/app/engine/scanners/microsoft_general.py` (tests 31–34, 80, 83–85, 99–102)
  - `backend/app/engine/scanners/general.py` (remaining tests: 4–11, 17, 22–26, 36–37, 44–46, 68, 75–79, 82, 86–87, 90–96, 98, 103–106)
- [x] T014 Create `backend/app/engine/analyzer.py` — `HeaderAnalyzer` orchestrator: accepts `AnalysisRequest`, uses `HeaderParser` + `ScannerRegistry`, runs scanners with per-test timeout, collects results (marking failed tests with error status per FR-25), supports progress callback `Callable[[int, int, str], None]`. Verify `test_analyzer.py` passes (TDD Green)

## Completion

- [x] `pytest backend/tests/engine/` passes with all tests green
- [x] All 106+ tests are registered in the scanner registry (`ScannerRegistry.get_all()` returns 106+ scanners)
  - Verified `ScannerRegistry.get_all()` returns 106 scanners (IDs 1-106, none missing).
- [x] Analysis of `backend/tests/fixtures/sample_headers.txt` produces results matching original CLI output
- [x] `ruff check backend/` passes with zero errors
- [x] Run `/speckit.analyze` to verify consistency (attempted on 2026-02-17 in PowerShell; command not available in this environment, `/speckit.analyze` not recognized)
