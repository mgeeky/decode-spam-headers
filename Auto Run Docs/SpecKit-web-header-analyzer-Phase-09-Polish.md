# Phase 09: Polish & Cross-Cutting Concerns

This phase performs final integration, accessibility audit, responsive testing, linting validation, coverage verification, performance benchmarking, and documentation. By the end of this phase, the complete application flow works end-to-end, meets all quality gates (WCAG 2.1 AA, responsive 320–2560px, coverage ≥80%, linting clean), and the README is updated.

## Spec Kit Context

- **Feature:** 1-web-header-analyzer
- **Specification:** .specify/specs/1-web-header-analyzer/spec.md (all NFRs)
- **Plan:** .specify/specs/1-web-header-analyzer/plan.md
- **Tasks:** .specify/specs/1-web-header-analyzer/tasks.md
- **Constitution:** .specify/memory/constitution.md (all principles P1–P8)

## Dependencies

- **Requires ALL previous phases (1–8)** completed
- All components exist, all backend endpoints operational, all tests passing

## Tasks

- [x] T046 Wire all components together in `frontend/src/app/page.tsx` — integrate HeaderInput, FileDropZone, AnalysisControls, AnalyseButton, ProgressIndicator, ReportContainer, CaptchaChallenge into the single-view application with correct data flow. Ensure: input feeds to analysis hook, progress hook drives progress indicator, result feeds to report container, 429 errors trigger CAPTCHA modal, cache hook restores state on mount. Notes: added AnalysisControls + CAPTCHA retry flow, extended analysis hook for bypass token handling, confirmed cache restore.
- [x] T047 Verify WCAG 2.1 AA compliance across all components (NFR-03) — ARIA labels, keyboard nav order, focus indicators, colour contrast ratios (dark theme). Fix violations. Test with screen reader simulation. Ensure all interactive elements have visible focus states. Notes: added keyboard-accessible file picker with ARIA descriptions, focus-visible outlines on drop zone/summary/search fields, boosted low-contrast text from 40% to 60%, linked CAPTCHA dialog description, added file picker tests; ran `npx vitest run src/__tests__/FileDropZone.test.tsx`.
- [x] T048 [P] Verify responsive layout 320px–2560px (NFR-04) at breakpoints: 320px, 768px, 1024px, 1440px, 2560px. No horizontal scroll, no overlapping elements, readable text. Fix any layout issues discovered. Notes: stacked control cards on small screens, added min-w-0 + flex-wrap on report UI, and break-words handling for long header values, hop chain hostnames/IPs, and search pills to prevent overflow.
- [x] T049 [P] Run full linting pass — `ruff check backend/` and `ruff format backend/` zero errors; `npx eslint src/` and `npx prettier --check src/` zero errors; no `any` types in TypeScript. Fix all violations. Notes: ruff formatted backend files, removed unsupported `aria-invalid` on file drop button, ran prettier on CAPTCHA + analysis tests.
- [x] T050 [P] Run full test suites and verify coverage — `pytest backend/tests/ --cov` ≥80% new modules (NFR-06); `npx vitest run --coverage` ≥80% new components (NFR-07). Add missing tests if coverage is below threshold. Notes: added pytest-cov + coverage-v8 deps; reset legacy adapter context to avoid cross-run state, updated HomePage test for report container; `pytest backend/tests/ --cov` passes and backend/app coverage 82%; `npx vitest run --coverage` passes with 83.35% overall.
- [x] T051 [P] Verify initial page load <3s on simulated 4G (constitution P7). Use Lighthouse with Slow 4G preset. Target score ≥90. Fix blocking resources or missing lazy-loading if score is below target. Notes: Lighthouse CLI (perf preset, mobile form factor, Slow 4G simulate) on http://localhost:3100 scored 91; LCP 2.46s, TTI 2.55s, FCP 0.75s, no blocking fixes required.
- [x] T052 [P] Benchmark analysis performance — full analysis of `backend/tests/fixtures/sample_headers.txt` completes within 10s (NFR-01). Profile slow scanners. Document results. Optimise if any scanner exceeds acceptable threshold. Notes: ran analyzer benchmark (0.34s, 106 tests) and per-scanner profiling; slowest was Domain Impersonation at 239ms. Documented in `docs/research/analysis-performance-benchmark.md`.
- [ ] T053 Update `README.md` with web interface section: description, local run instructions for backend (`uvicorn backend.app.main:app`) and frontend (`npm run dev`), environment variable documentation, test run commands (`pytest`, `vitest`, `playwright test`), screenshots placeholder

## Completion

- [ ] Complete flow works end-to-end: paste headers → configure tests → analyse → view report → export
- [ ] File drop flow works: drop EML → auto-populate → analyse → report
- [ ] Cache flow works: analyse → reload → see cached results → clear cache
- [ ] Rate limiting flow works: exceed limit → CAPTCHA modal → solve → retry succeeds
- [ ] `pytest backend/tests/` passes with ≥80% coverage on new modules
- [ ] `npx vitest run --coverage` passes with ≥80% coverage on new components
- [ ] `ruff check backend/` — zero errors
- [ ] `npx eslint src/` — zero errors
- [ ] `npx prettier --check src/` — zero errors
- [ ] No `any` types in TypeScript
- [ ] WCAG 2.1 AA compliant (ARIA labels, keyboard nav, contrast ratios)
- [ ] Responsive at 320px, 768px, 1024px, 1440px, 2560px — no layout issues
- [ ] Lighthouse score ≥90 on Slow 4G preset
- [ ] Analysis completes within 10s for sample headers
- [ ] README.md updated with web interface documentation
- [ ] Run `/speckit.analyze` to verify consistency
