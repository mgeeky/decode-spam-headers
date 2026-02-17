# Phase 03: US1 — Header Input & Submission

This phase implements the user-facing input layer: a multi-line textarea for pasting SMTP headers, a drag-and-drop zone for EML/TXT files, and an analyse button with keyboard shortcut. The dark hacker theme becomes visible. By the end of this phase, users can paste text, drop files to auto-populate, and trigger analysis (though the full analysis pipeline connects in Phase 5). TDD Red-Green: write failing component tests first, then implement components.

## Spec Kit Context

- **Feature:** 1-web-header-analyzer
- **Specification:** .specify/specs/1-web-header-analyzer/spec.md (FR-01, FR-02, FR-05, FR-14, FR-15)
- **Plan:** .specify/specs/1-web-header-analyzer/plan.md
- **Tasks:** .specify/specs/1-web-header-analyzer/tasks.md
- **User Story:** US1 — Header Input & Submission (Scenarios 1, 2)
- **Constitution:** .specify/memory/constitution.md (TDD: P6, UX: P7)

## Dependencies

- **Requires Phase 01** completed (frontend project initialised, design tokens, types)
- **Does NOT require Phase 02** (engine) — components are UI-only at this stage

## Design Reference

- Background: `#1e1e2e`, Surface: `#282a36`, Text: `#f8f8f2`
- Monospace font for header text areas
- FontAwesome icons for actions (paste, upload, clear, analyse)
- Responsive from 320px to 2560px (NFR-04)
- All controls keyboard accessible (NFR-02)
- Input validation: empty input blocked, oversized >1MB rejected with user-friendly error (NFR-10)

## Tasks

- [x] T015 [US1] Write failing tests (TDD Red) in `frontend/src/__tests__/HeaderInput.test.tsx` (render, paste simulation, empty/oversized validation), `frontend/src/__tests__/FileDropZone.test.tsx` (render, drop event, file type filtering), and `frontend/src/__tests__/AnalyseButton.test.tsx` (render, disabled state, Ctrl+Enter shortcut)
- [x] T016 [US1] Create main page layout in `frontend/src/app/page.tsx` with dark hacker theme (#1e1e2e background, monospace code areas, project title). Responsive from 320px to 2560px (NFR-04)
- [x] T017 [P] [US1] Create `frontend/src/components/HeaderInput.tsx` — multi-line textarea for SMTP headers with placeholder, character count, clear button (FontAwesome icon), monospace styling, keyboard accessible (NFR-02), validation for empty and oversized >1MB input (NFR-10). Verify `HeaderInput.test.tsx` passes (TDD Green)
- [x] T018 [P] [US1] Create `frontend/src/components/FileDropZone.tsx` — drag-and-drop zone accepting `.eml` and `.txt` files, reads client-side via File API (FR-02), populates HeaderInput on drop, shows drag-over highlight and rejection feedback, FontAwesome upload icon. Verify `FileDropZone.test.tsx` passes (TDD Green)
- [x] T019 [US1] Create `frontend/src/components/AnalyseButton.tsx` — primary action button with FontAwesome analyse icon, Ctrl+Enter shortcut (FR-05), disabled when input empty, loading state during analysis (NFR-05), hacker accent colour. Verify `AnalyseButton.test.tsx` passes (TDD Green)

Note: `npx vitest run src/__tests__/AnalyseButton.test.tsx` passes; Vitest emits existing act() environment warnings.

## Completion

- [x] All vitest tests pass: `npx vitest run src/__tests__/HeaderInput.test.tsx src/__tests__/FileDropZone.test.tsx src/__tests__/AnalyseButton.test.tsx`
- [x] User can paste text into the header input area
- [x] User can drop an EML/TXT file and see it auto-populate the input
- [x] Analyse button is disabled when input is empty
- [x] Ctrl+Enter keyboard shortcut triggers the analyse action
- [ ] Dark hacker theme is visible with correct colour palette
- [ ] Validation shows user-friendly errors for empty and oversized input
- [ ] `npx eslint src/` and `npx prettier --check src/` pass with zero errors
- [ ] Run `/speckit.analyze` to verify consistency

Note: Wired `FileDropZone` into the main page to populate the header input state on drop.
