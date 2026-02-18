# Phase 06: US4 — Interactive Report Rendering

This phase implements the full interactive report: collapsible test result cards with colour-coded severity, hop chain flow visualisation, security appliances summary, search/filter bar, and export to HTML/JSON. By the end of this phase, users receive a complete, interactive analysis report. TDD Red-Green: write all failing component tests first, then implement each component.

## Spec Kit Context

- **Feature:** 1-web-header-analyzer
- **Specification:** .specify/specs/1-web-header-analyzer/spec.md (FR-07, FR-08, FR-09, FR-20, FR-21, FR-25)
- **Plan:** .specify/specs/1-web-header-analyzer/plan.md
- **Tasks:** .specify/specs/1-web-header-analyzer/tasks.md
- **Data Model:** .specify/specs/1-web-header-analyzer/data-model.md (TestResult, HopChainNode, SecurityAppliance, AnalysisReport)
- **User Story:** US4 — Interactive Report Rendering (Scenario 1, steps 7–8)
- **Constitution:** .specify/memory/constitution.md (TDD: P6, UX: P7)

## Dependencies

- **Requires Phase 05** completed (analysis results available to render)

## Severity Colour Mapping

- **Spam:** `#ff5555` (red) — FontAwesome warning/ban icon
- **Suspicious:** `#ffb86c` (amber) — FontAwesome exclamation icon
- **Clean:** `#50fa7b` (green) — FontAwesome check icon
- **Info:** `#bd93f9` (purple) — FontAwesome info icon
- **Error:** error indicator with failure explanation (FR-25)

## Component Architecture

```
ReportContainer
├── Summary Stats (total tests, passed, failed, severity breakdown)
├── ReportSearchBar (filter by text match)
├── ReportExport (HTML / JSON download buttons)
├── SecurityAppliancesSummary (detected security products as badges)
├── HopChainVisualisation (vertical flow diagram of mail server hops)
└── TestResultCard[] (one per test result, collapsible, severity-coloured)
```

## Tasks

- [x] T030 [US4] Write failing tests (TDD Red) in `frontend/src/__tests__/report/TestResultCard.test.tsx` (each severity level, expand/collapse, error indicator), `HopChainVisualisation.test.tsx` (render with sample hops), `ReportSearchBar.test.tsx` (filter simulation), `ReportExport.test.tsx` (export trigger), `SecurityAppliancesSummary.test.tsx` (render with sample appliances, empty state), `ReportContainer.test.tsx` (full report with mixed results)
- [x] T031 [P] [US4] Create `frontend/src/components/report/TestResultCard.tsx` — collapsible card per test result. Severity-coloured indicator (red=spam, amber=suspicious, green=clean per FR-09), header name, monospace value, analysis text. Failed tests show error indicator (FR-25). Expand/collapse with animation, keyboard accessible (NFR-02). Verify `TestResultCard.test.tsx` passes (TDD Green)
- [x] T032 [P] [US4] Create `frontend/src/components/report/HopChainVisualisation.tsx` — vertical flow diagram of mail server hop chain (FR-08): hostname, IP, timestamp, server version, connecting arrows. FontAwesome server/network icons. Responsive. Verify `HopChainVisualisation.test.tsx` passes (TDD Green)
- [x] T033 [P] [US4] Create `frontend/src/components/report/ReportSearchBar.tsx` — search/filter bar above report (FR-20). Filters by text match against test name, header name, or analysis text. Highlights matches, shows count. FontAwesome search icon, Escape to clear. Verify `ReportSearchBar.test.tsx` passes (TDD Green)
- [ ] T034 [P] [US4] Create `frontend/src/components/report/ReportExport.tsx` — export as HTML (styled standalone page) or JSON (raw data) per FR-21. FontAwesome download icons, triggers browser download. Verify `ReportExport.test.tsx` passes (TDD Green)
- [ ] T035 [US4] Create `frontend/src/components/report/SecurityAppliancesSummary.tsx` — summary listing detected email security products as badges/tags with FontAwesome shield icons. Handle empty state (no appliances detected). Verify `SecurityAppliancesSummary.test.tsx` passes (TDD Green)
- [ ] T036 [US4] Create `frontend/src/components/report/ReportContainer.tsx` — top-level wrapper receiving `AnalysisReport`. Renders: summary stats (total tests, passed, failed, severity breakdown), `TestResultCard` list, `HopChainVisualisation`, `SecurityAppliancesSummary`, `ReportSearchBar`, `ReportExport`. FontAwesome summary icons. Verify `ReportContainer.test.tsx` passes (TDD Green)

## Completion

- [ ] All vitest tests pass: `npx vitest run src/__tests__/report/`
- [ ] Report renders all test results as collapsible cards with correct severity colours
- [ ] Hop chain displays as a vertical visual flow with server details and connecting arrows
- [ ] Security appliances show as badges; empty state handled gracefully
- [ ] Search filters results in real-time across test name, header name, and analysis text
- [ ] Export JSON produces a valid JSON file containing all results
- [ ] Export HTML produces a styled standalone page viewable in any browser
- [ ] All report components are keyboard accessible
- [ ] Linting passes (`npx eslint src/`, `npx prettier --check src/`)
- [ ] Run `/speckit.analyze` to verify consistency
