# Phase 04: US2 — Test Selection & Configuration

This phase implements the test selection panel and analysis configuration controls. Users can see all 106+ analysis tests listed with checkboxes, select/deselect all, search/filter by name, and toggle DNS resolution and decode-all options. The backend `GET /api/tests` endpoint provides the test listing. TDD Red-Green: write failing tests first, then implement.

## Spec Kit Context

- **Feature:** 1-web-header-analyzer
- **Specification:** .specify/specs/1-web-header-analyzer/spec.md (FR-03, FR-04, FR-17, FR-18, FR-19, FR-23, FR-24)
- **Plan:** .specify/specs/1-web-header-analyzer/plan.md
- **Tasks:** .specify/specs/1-web-header-analyzer/tasks.md
- **API Contract:** .specify/specs/1-web-header-analyzer/contracts/api.yaml (`GET /api/tests`)
- **User Story:** US2 — Test Selection & Configuration (Scenario 3)
- **Constitution:** .specify/memory/constitution.md (TDD: P6, UX: P7)

## Dependencies

- **Requires Phase 01** completed (frontend project, types, API client)
- **Requires Phase 02** completed (scanner registry with 106+ tests for the backend endpoint)
- **Can run in parallel with Phase 03** (US1) after Phase 02 completes

## Tasks

- [x] T020 [US2] Write failing test (TDD Red) in `backend/tests/api/test_tests_router.py` — verify `GET /api/tests` returns 200 with all registered test IDs and names. Use httpx AsyncClient against the FastAPI test app
- [x] T021 [US2] Create `backend/app/schemas/tests.py` (response schema) and `backend/app/routers/tests.py` — FastAPI router with `GET /api/tests` returning all available tests (id, name, category) from scanner registry. Register router in `backend/app/main.py`. Verify `test_tests_router.py` passes (TDD Green)
- [x] T022 [US2] Write failing tests (TDD Red) in `frontend/src/__tests__/TestSelector.test.tsx` (render with mocked list, select/deselect all, search filtering) and `frontend/src/__tests__/AnalysisControls.test.tsx` (render, toggle states, keyboard accessibility)
- [x] T023 [P] [US2] Create `frontend/src/components/TestSelector.tsx` — dropdown with checkboxes per test, fetches list from `GET /api/tests`, "Select All"/"Deselect All" buttons (FR-04), text search/filter (FR-23), grouped by vendor/category (FR-24), FontAwesome icons. Verify `TestSelector.test.tsx` passes (TDD Green)
- [x] T024 [P] [US2] Create `frontend/src/components/AnalysisControls.tsx` — panel containing TestSelector, DNS resolution toggle (off by default, FR-18), decode-all toggle (FR-19), FontAwesome toggle icons, keyboard accessible (NFR-02). Verify `AnalysisControls.test.tsx` passes (TDD Green)

## Completion

- [x] `pytest backend/tests/api/test_tests_router.py` passes
- [x] `GET /api/tests` returns all 106+ tests with id, name, and category
- [x] All vitest tests pass: `npx vitest run src/__tests__/TestSelector.test.tsx src/__tests__/AnalysisControls.test.tsx`
- [x] Test selector renders all 106+ tests with checkboxes
- [x] Select All / Deselect All buttons work correctly
- [x] Search/filter narrows visible tests by name
- [x] DNS resolution toggle defaults to off
- [x] Decode-all toggle is functional
- [x] All controls are keyboard accessible (Tab, Enter, Space)
- [x] Linting passes (`ruff check backend/`, `npx eslint src/`)
- [ ] Run `/speckit.analyze` to verify consistency

Note: Verified Select All/Deselect All behavior via `TestSelector.test.tsx` ("selects and deselects all tests") on 2026-02-18.
