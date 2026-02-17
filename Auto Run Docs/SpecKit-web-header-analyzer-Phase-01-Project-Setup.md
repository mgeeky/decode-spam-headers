# Phase 01: Project Setup & Scaffolding

This phase initialises the complete project structure for both the FastAPI backend and NextJS frontend, including all tooling, linting, dependency configuration, Playwright installation, shared types, design tokens, and API client abstraction. By the end of this phase, both servers start successfully, linting passes on both sides, and the Playwright test runner is configured.

## Spec Kit Context

- **Feature:** 1-web-header-analyzer
- **Specification:** .specify/specs/1-web-header-analyzer/spec.md
- **Plan:** .specify/specs/1-web-header-analyzer/plan.md
- **Tasks:** .specify/specs/1-web-header-analyzer/tasks.md
- **Data Model:** .specify/specs/1-web-header-analyzer/data-model.md
- **API Contract:** .specify/specs/1-web-header-analyzer/contracts/api.yaml
- **Quickstart:** .specify/specs/1-web-header-analyzer/quickstart.md
- **Constitution:** .specify/memory/constitution.md

## Architecture Reference

```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py              # Minimal FastAPI app skeleton
│   └── core/
│       └── config.py        # Pydantic BaseSettings
├── tests/
│   └── __init__.py
├── pyproject.toml
└── requirements.txt

frontend/
├── src/
│   ├── app/
│   │   └── page.tsx         # Blank page placeholder
│   ├── types/
│   │   └── analysis.ts      # TypeScript interfaces
│   ├── lib/
│   │   └── api-client.ts    # Typed fetch wrapper
│   └── styles/
│       └── design-tokens.ts # Centralised colour/spacing tokens
├── e2e/                     # Playwright test directory (empty for now)
├── playwright.config.ts
├── vitest.config.ts
├── tsconfig.json
├── tailwind.config.ts
├── .eslintrc.json
├── .prettierrc
└── package.json
```

## Design Tokens Reference

The hacker-themed dark colour palette (from spec FR-14):
- Background: `#1e1e2e`
- Surface: `#282a36`
- Text: `#f8f8f2`
- Spam (red): `#ff5555`
- Suspicious (amber): `#ffb86c`
- Clean (green): `#50fa7b`
- Accent (purple): `#bd93f9`
- Info: `#8be9fd`

## Tasks

- [x] T001 Initialise Python 3.13 backend project with FastAPI, uvicorn, pytest, pytest-asyncio, httpx, and ruff in `backend/pyproject.toml`. Create `backend/requirements.txt`, `backend/app/__init__.py`, and `backend/app/main.py` with minimal FastAPI app skeleton that returns 200 on root endpoint
- [x] T002 Initialise NextJS + TypeScript frontend project in `frontend/`. Configure `frontend/tsconfig.json` with strict mode. Install and configure Tailwind CSS in `frontend/tailwind.config.ts` with hacker-themed colour palette (#1e1e2e backgrounds, red spam, amber suspicious, green clean). Install FontAwesome packages. Configure eslint and prettier in `frontend/.eslintrc.json` and `frontend/.prettierrc`. Install Playwright (`npm init playwright@latest`) with `frontend/playwright.config.ts` and `@axe-core/playwright`. Configure `webServer` array for both uvicorn (port 8000) and NextJS (port 3000), `testDir: './e2e'`, `fullyParallel: true`. Exclude `e2e/` from vitest config
- [x] T003 [P] Create `backend/app/core/config.py` with Pydantic BaseSettings for CORS origins, rate limit thresholds, analysis timeout (30s), and debug flag — all configurable via environment variables
- [x] T004 [P] Create `frontend/src/types/analysis.ts` with TypeScript interfaces: `HeaderInput`, `AnalysisConfig` (test IDs, resolve flag, decode-all flag), `TestResult` (id, name, header, value, analysis, description, severity, status), `AnalysisReport` (results, hopChain, securityAppliances, metadata), `AnalysisProgress` (current test, total, percentage, elapsed). Refer to `.specify/specs/1-web-header-analyzer/data-model.md` for the complete entity definitions
- [x] T005 [P] Create `frontend/src/lib/api-client.ts` — API client abstraction wrapping fetch with base URL from environment, JSON defaults, error handling, and typed response generics. Must support SSE streaming via ReadableStream for the analysis endpoint
- [x] T006 [P] Create `frontend/src/styles/design-tokens.ts` — centralised design tokens: colours (#1e1e2e background, #282a36 surface, #f8f8f2 text, #ff5555 spam, #ffb86c suspicious, #50fa7b clean, #bd93f9 accent), font families (mono/sans), spacing scale, and border-radius values

## Completion

- [x] Backend starts with `uvicorn backend.app.main:app` and returns 200 on root
- [x] Frontend starts with `npm run dev` and renders a blank page
- [x] Linting passes on both sides (`ruff check backend/`, `npx eslint src/`, `npx prettier --check src/`)
- [x] Playwright test runner executes with `npx playwright test` (no tests yet, but config loads without error)
- [x] TypeScript compilation succeeds with zero errors in strict mode
- [ ] Run `/speckit.analyze` to verify consistency (attempted, but command not available in this environment)
