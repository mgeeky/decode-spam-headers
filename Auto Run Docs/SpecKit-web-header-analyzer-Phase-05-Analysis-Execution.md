# Phase 05: US3 — Analysis Execution & Progress

This phase implements the core analysis pipeline: the backend `POST /api/analyse` endpoint with SSE progress streaming, and the frontend `useAnalysis` hook and progress indicator. After this phase, users can submit headers, see real-time progress with a countdown timer, and receive analysis results. Partial failures and 30-second timeouts are handled gracefully. TDD Red-Green approach throughout.

## Spec Kit Context

- **Feature:** 1-web-header-analyzer
- **Specification:** .specify/specs/1-web-header-analyzer/spec.md (FR-06, FR-10, FR-16, FR-22, FR-25, NFR-09, NFR-10, NFR-13, NFR-14)
- **Plan:** .specify/specs/1-web-header-analyzer/plan.md (SSE streaming section)
- **Tasks:** .specify/specs/1-web-header-analyzer/tasks.md
- **API Contract:** .specify/specs/1-web-header-analyzer/contracts/api.yaml (`POST /api/analyse`)
- **User Story:** US3 — Analysis Execution & Progress (Scenario 1, steps 5–6)
- **Constitution:** .specify/memory/constitution.md (TDD: P6, UX: P7)

## Dependencies

- **Requires Phase 02** completed (engine: HeaderAnalyzer, ScannerRegistry, HeaderParser)
- **Requires Phase 03** completed (HeaderInput, AnalyseButton for triggering)
- **Requires Phase 04** completed (AnalysisControls for config)

## SSE Streaming Design

The `POST /api/analyse` endpoint uses Server-Sent Events:
1. Client sends headers + config via POST
2. Server validates input, starts analysis
3. Server streams `event: progress` messages: `{current, total, testName, elapsed}`
4. Server sends `event: result` with the final `AnalysisResult`
5. Server closes the connection

Frontend uses `fetch` with `ReadableStream` reader (not native `EventSource`, which doesn't support POST).

## Tasks

- [x] T025 [US3] Write failing tests (TDD Red) in `backend/tests/api/test_analysis_router.py` — happy path (valid headers → 200 with SSE progress + result), error path (empty → 400), oversized (>1MB → 413), partial failure (some tests error → mixed results per FR-25), timeout (30s limit per NFR-13, partial results per NFR-14)
- [x] T026 [US3] Create `backend/app/schemas/analysis.py` (request/response schemas) and `backend/app/routers/analysis.py` — FastAPI router with `POST /api/analyse` using SSE for progress streaming. Accepts headers string + config (test IDs, resolve, decode-all). Invokes `HeaderAnalyzer` with 30s timeout (NFR-13). Streams progress events then final result. Sanitises input (NFR-09), validates size ≤1MB (NFR-10). Stateless — no job_id, no in-memory state (Assumption 3). Register router in `backend/app/main.py`. Verify `test_analysis_router.py` passes (TDD Green)
- [x] T027 [US3] Write failing tests (TDD Red) in `frontend/src/__tests__/ProgressIndicator.test.tsx` (render at various states, timeout display) and `frontend/src/__tests__/useAnalysis.test.ts` (hook state transitions, SSE handling)
- [x] T028 [P] [US3] Create `frontend/src/hooks/useAnalysis.ts` — custom hook managing analysis lifecycle. Submits to `POST /api/analyse` via API client, consumes SSE stream for real-time progress (no polling). States: idle, submitting, analysing (with progress), complete, error, timeout. Returns: `submit()`, `cancel()`, `progress`, `result`, `error`, `status`. Verify `useAnalysis.test.ts` passes (TDD Green)
- [x] T029 [P] [US3] Create `frontend/src/components/ProgressIndicator.tsx` — progress bar with percentage, current test name (FR-22), countdown timer from 30s (NFR-13), elapsed time. Colour-coded: green progressing, amber near timeout, red on timeout. FontAwesome spinner. Timeout notification listing incomplete tests (NFR-14). Verify `ProgressIndicator.test.tsx` passes (TDD Green)

## Completion

- [x] `pytest backend/tests/api/test_analysis_router.py` passes (all paths: happy, error, oversized, partial failure, timeout)
- [x] All vitest tests pass: `npx vitest run src/__tests__/ProgressIndicator.test.tsx src/__tests__/useAnalysis.test.ts`
- [ ] Submitting headers triggers backend analysis with SSE streaming
- [ ] Progress bar updates in real-time showing current test name and percentage
- [ ] Countdown timer counts down from 30 seconds
- [ ] Partial failures show inline error indicators per FR-25
- [ ] Timeout at 30s displays partial results with notification listing incomplete tests
- [ ] Empty input returns 400, oversized >1MB returns 413
- [ ] Linting passes on both sides
- [ ] Run `/speckit.analyze` to verify consistency
