# Phase 08: US6 — Security & Operational Readiness

This phase protects the analysis service from abuse with per-IP rate limiting and CAPTCHA challenge, exposes a health-check endpoint for monitoring, and wires all routers and middleware into the FastAPI application. The frontend displays a CAPTCHA modal when rate-limited. TDD Red-Green approach throughout.

## Spec Kit Context

- **Feature:** 1-web-header-analyzer
- **Specification:** .specify/specs/1-web-header-analyzer/spec.md (NFR-11, NFR-12, NFR-15, NFR-16)
- **Plan:** .specify/specs/1-web-header-analyzer/plan.md
- **Tasks:** .specify/specs/1-web-header-analyzer/tasks.md
- **API Contract:** .specify/specs/1-web-header-analyzer/contracts/api.yaml (`GET /api/health`, `POST /api/captcha/verify`)
- **User Story:** US6 — Security & Operational Readiness
- **Constitution:** .specify/memory/constitution.md (TDD: P6)

## Dependencies

- **Requires Phase 05** completed (analysis endpoint for rate limiting to protect)
- **Requires Phase 01** completed (config.py for rate limit thresholds)

## Rate Limiting Design

- **Mechanism:** Per-IP sliding window counter (async-safe, in-memory)
- **Threshold:** Configurable via `config.py` environment variables
- **Response:** HTTP 429 with `Retry-After` header and CAPTCHA challenge token
- **CAPTCHA:** Server-generated visual noise (randomly distorted text rendered as image)
- **Bypass:** HMAC-signed token (5-minute expiry) returned on successful CAPTCHA solve
- **Trade-off:** Per-instance counters — acceptable for initial release; shared Redis store upgradeable later

## Tasks

- [x] T040 [US6] Write failing tests (TDD Red) in `backend/tests/api/test_rate_limiter.py` (rate limiting triggers at threshold, 429 response with CAPTCHA challenge), `backend/tests/api/test_captcha.py` (challenge generation, verification, bypass token), `backend/tests/api/test_health.py` (health endpoint returns correct status), and `frontend/src/__tests__/CaptchaChallenge.test.tsx` (render modal, display CAPTCHA image, submit answer, handle success/failure states, keyboard accessibility)
- [x] T041 [US6] Create `backend/app/middleware/rate_limiter.py` — per-IP sliding window rate limiter (async-safe in-memory). Configurable limit via `config.py`. Returns 429 with Retry-After header and CAPTCHA challenge token (NFR-11, NFR-12). Note: per-instance counters — acceptable for initial release; shared store upgradeable later. Verify `test_rate_limiter.py` passes (TDD Green)
- [x] T042 [US6] Create `backend/app/routers/captcha.py` — `POST /api/captcha/verify` endpoint. Server-generated visual noise CAPTCHA (randomly distorted text). Returns HMAC-signed bypass token (5-minute expiry) on success. Token exempts IP from rate limiting. Response schema in `backend/app/schemas/captcha.py`. Verify `test_captcha.py` passes (TDD Green)
- [x] T043 [P] [US6] Create `frontend/src/components/CaptchaChallenge.tsx` — modal on 429 response. Displays CAPTCHA image, on verification stores bypass token and retries original request. FontAwesome lock/unlock icons. Keyboard accessible (NFR-02). Verify `CaptchaChallenge.test.tsx` passes (TDD Green)
- [x] T044 [US6] Create `backend/app/schemas/health.py` and `backend/app/routers/health.py` — `GET /api/health` returning status (up/degraded/down), version, uptime, scanner count (NFR-15). Verify `test_health.py` passes (TDD Green)
- [x] T045 [US6] Register all routers and middleware in `backend/app/main.py` — CORS middleware (frontend origin), rate limiter, routers (analysis, tests, health, captcha). Verify stateless operation (NFR-16). Note: rate limiter per-instance state is accepted trade-off (see T041)

## Completion

- [x] `pytest backend/tests/api/test_rate_limiter.py backend/tests/api/test_captcha.py backend/tests/api/test_health.py` all pass
- [x] All vitest tests pass: `npx vitest run src/__tests__/CaptchaChallenge.test.tsx`
- [x] Exceeding rate limit returns HTTP 429 with Retry-After header and CAPTCHA challenge
- [ ] Solving CAPTCHA returns HMAC-signed bypass token (5-minute expiry)
- [ ] Bypass token exempts IP from rate limiting on subsequent requests
- [ ] `GET /api/health` returns `{status, version, uptime, scannerCount}`
- [x] All routers and CORS middleware are registered in `main.py`
- [ ] Application starts statelessly — no database, no session management
- [ ] CAPTCHA modal is keyboard accessible (Tab, Enter, Escape to close)
- [ ] Linting passes on both sides
- [ ] Run `/speckit.analyze` to verify consistency
