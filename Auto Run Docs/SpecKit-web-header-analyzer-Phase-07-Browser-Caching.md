# Phase 07: US5 — Browser Caching

This phase implements browser-side persistence using localStorage so that previously submitted headers and analysis results survive page reloads. Users can view cached results immediately on return visits and explicitly clear the cache. TDD Red-Green: write failing tests first, then implement the cache hook and page integration.

## Spec Kit Context

- **Feature:** 1-web-header-analyzer
- **Specification:** .specify/specs/1-web-header-analyzer/spec.md (FR-12, FR-13)
- **Plan:** .specify/specs/1-web-header-analyzer/plan.md
- **Tasks:** .specify/specs/1-web-header-analyzer/tasks.md
- **User Story:** US5 — Browser Caching (Scenario 4)
- **Constitution:** .specify/memory/constitution.md (TDD: P6)

## Dependencies

- **Requires Phase 03** completed (HeaderInput for headers text)
- **Requires Phase 06** completed (ReportContainer for cached report display)

## localStorage Key Namespace

Use a consistent prefix to avoid collisions:
- `wha:headers` — last submitted header text
- `wha:config` — last analysis config (selected tests, toggles)
- `wha:result` — last analysis result (full AnalysisReport JSON)
- `wha:timestamp` — when the cache was last written

## Tasks

- [x] T037 [US5] Write failing tests (TDD Red) in `frontend/src/__tests__/useAnalysisCache.test.ts` (save/load/clear with mocked localStorage, size awareness) and `frontend/src/__tests__/page.test.tsx` (cache restoration on mount, clear cache button)
- [ ] T038 [P] [US5] Create `frontend/src/hooks/useAnalysisCache.ts` — hook managing localStorage with namespaced keys. Saves: headers text, analysis config, analysis result. Size-aware (warns near limits). Methods: `save()`, `load()`, `clear()`, `hasCachedData()`. Verify `useAnalysisCache.test.ts` passes (TDD Green)
- [ ] T039 [US5] Integrate caching into `frontend/src/app/page.tsx` — on mount restore cached data, render cached report, "Clear Cache" button with FontAwesome trash icon (FR-13), subtle indicator when viewing cached results. Verify `page.test.tsx` passes (TDD Green)

## Completion

- [ ] All vitest tests pass: `npx vitest run src/__tests__/useAnalysisCache.test.ts src/__tests__/page.test.tsx`
- [ ] After analysis, headers and results are saved to localStorage
- [ ] Page refresh restores the previous analysis (headers in input, report rendered)
- [ ] "Clear Cache" button removes all stored data and resets the view to empty state
- [ ] Subtle indicator distinguishes cached results from fresh analysis
- [ ] Size-awareness warns if localStorage is near capacity
- [ ] Linting passes (`npx eslint src/`, `npx prettier --check src/`)
- [ ] Run `/speckit.analyze` to verify consistency
