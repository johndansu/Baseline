# Backend Implementation Plan

_Owner: Baseline Engineering_
_Last updated: 2026-02-21_

## Goal
Ship a production-grade Baseline backend that is contract-stable, secure-by-default, observable, and fully test-gated.

## Principles
- OpenAPI is the contract source for `/v1` routes.
- No undocumented behavior in handlers.
- Deterministic error and exit behavior.
- Security controls enabled by default.
- Every feature ships with tests and release gates.

## Current Baseline
- API server exists with auth, scans, policies, rulesets, audit events.
- SQLite store exists and already persists API keys/audit/integration jobs.
- Main gap is maturity: modularity, strict contract checks, security hardening, observability, and end-to-end test confidence.

## Delivery Order

## Progress Snapshot
- Completed: OpenAPI/runtime contract regression harness (`internal/api/contract_test.go`).
- Completed: Core response-shape contract checks for dashboard/scans/reports/policies/audit.
- Completed: OpenAPI drift fix for liveness alias (`/livez`) in `internal/api/assets/openapi.yaml`.
- In progress: `server.go` decomposition (handlers + router + middleware + errors extraction completed; remaining file-size reduction still pending).
- Completed: Versioned SQLite migration runner with legacy upgrade coverage (`internal/api/store.go`, `internal/api/store_migration_test.go`).
- Completed: API key hash-at-rest migration with keyed hashing support and compatibility tests.
- Completed: Middleware rate limits and abuse controls for unauth/authenticated/auth endpoints with deterministic `429` behavior.

## Phase 0: Contract Freeze and Route Validation (Week 1)
- [ ] Freeze API contract and mark unsupported fields in `internal/api/assets/openapi.yaml`.
- [x] Add route-to-contract regression tests in `internal/api/contract_test.go`.
- [x] Add response shape checks for key endpoints:
- `GET /v1/dashboard`
- `GET|POST /v1/scans`
- `GET /v1/scans/{id}/report?format=json|text|sarif`
- `GET /v1/policies`
- `GET /v1/audit/events`
- [x] Add CI job to fail on spec/runtime drift in `.github/workflows/ci.yml`.

Done when:
- Runtime routes and OpenAPI are aligned with deterministic tests.

## Phase 1: API Server Refactor for Maintainability (Week 1-2)
- [ ] Split `internal/api/server.go` into focused files without behavior change:
- [x] `internal/api/handlers_auth.go`
- [x] `internal/api/handlers_projects_scans.go`
- [x] `internal/api/handlers_policies_rulesets.go`
- [x] `internal/api/handlers_audit_dashboard.go`
- [x] `internal/api/middleware.go`
- [x] `internal/api/errors.go`
- [x] `internal/api/router.go`
- [ ] Keep shared types in `internal/api/types.go`.
- [ ] Keep backward compatibility of existing endpoints and auth flow.
- [ ] Update tests to target per-handler modules in `internal/api/server_test.go`.

Done when:
- `server.go` is no longer monolithic and test suite remains green.

## Phase 2: Data Layer and Migration Discipline (Week 2)
- [x] Introduce schema versioning and migration runner in `internal/api/store.go`.
- [x] Add deterministic bootstrap path for fresh DB and upgrade path for existing DB.
- [x] Add indexes for common read paths:
- audit events by `created_at`
- scans by `project_id`, `created_at`
- keys by `id`, `revoked`
- [x] Add migration tests for upgrade safety in `internal/api/store_migration_test.go` and `internal/api/server_test.go`.

Done when:
- Old DB files upgrade safely and all queries remain performant under basic load tests.

## Phase 3: Security Hardening (Week 2-3)
- [x] Move API key storage from plaintext to hashed-at-rest in `internal/api/store.go`.
- [x] Preserve one-time key return semantics at creation endpoints in `internal/api/server.go`.
- [ ] Enforce RBAC on all mutating routes (admin-only where required).
- [x] Add request rate limits in middleware (`internal/api/middleware.go`).
- [x] Enforce strict body limits and payload validation (`internal/api/server.go`, `internal/api/config.go`).
- [x] Ensure secure default headers and cookie settings for dashboard sessions (`internal/api/middleware.go`).
- [x] Extend tests for auth/RBAC/rate-limit/validation in `internal/api/server_test.go`.

Done when:
- Key exfiltration risk is reduced and auth failures are deterministic.

## Phase 4: Workflow Reliability (Scans, Policies, Rulesets) (Week 3)
- [ ] Add idempotency safeguards for `POST /v1/scans` in `internal/api/server.go`.
- [ ] Validate scan payload schema and reject malformed payloads with stable errors.
- [ ] Stabilize policy version publish/list/read path behavior in:
- `internal/api/server.go`
- `internal/api/types.go`
- `internal/api/store.go`
- [ ] Stabilize ruleset publish/latest/version retrieval behavior and tests.
- [ ] Add contract-level SARIF/text/json report tests for scan reports.

Done when:
- Repeated submissions are safe and report outputs are contract-consistent.

## Phase 5: Observability and Ops (Week 3-4)
- [ ] Add request IDs and structured request logs in `internal/api/middleware.go`.
- [ ] Add lightweight metrics endpoint (`/metrics`) in `internal/api/server.go`.
- [ ] Strengthen readiness semantics to include DB and worker health.
- [ ] Improve audit event coverage for key lifecycle and policy changes.
- [ ] Add operator-oriented runbook snippets to `README.md` and `command.md`.

Done when:
- Operators can diagnose incidents from logs/metrics/readiness quickly.

## Phase 6: Dashboard-Backend Integration (Week 4)
- [ ] Connect dashboard data fetching to real endpoints in:
- `internal/api/assets/dashboard.js`
- `internal/api/dashboard.html`
- [ ] Align the static template expectations with API payloads:
- `frontend/dashboard.html`
- `frontend/dashboard.css`
- [ ] Ensure auth/session behavior is clear (API key vs session) and error states are rendered.
- [ ] Add integration checks so dashboard only calls implemented routes.

Done when:
- Dashboard works end-to-end against `baseline api serve` without hidden assumptions.

## Phase 7: Release Gates and Production Readiness (Week 4-5)
- [ ] Add backend e2e suite (auth, projects, scans, policies, rulesets, audit).
- [ ] Add contract checks to required CI branch protections.
- [ ] Add performance smoke tests for high-read endpoints.
- [ ] Run hardening gate before release:
- `go test ./...`
- `baseline check`
- API contract tests
- e2e suite
- [ ] Document rollback procedure and release checklist in `README.REMAINING.md`.

Done when:
- Backend changes are script-safe, test-gated, and release-ready.

## Ticket List by File (Execution Backlog)
- [ ] `internal/api/server.go`: extract handlers, enforce strict validation, idempotency, stable errors.
- [ ] `internal/api/store.go`: migrations, hashed API keys, indexed queries, safer writes.
- [ ] `internal/api/middleware.go` (new): auth guards, rate limits, headers, request IDs.
- [ ] `internal/api/router.go` (new): route registration, middleware chain, versioned API mount.
- [ ] `internal/api/errors.go` (new): unified API error schema and helpers.
- [ ] `internal/api/types.go`: lock response models and request payload structs.
- [ ] `internal/api/assets/openapi.yaml`: keep in sync with implemented runtime contract.
- [ ] `internal/api/server_test.go`: contract + security + regression coverage.
- [ ] `internal/api/config.go`: defaults for body limits, timeouts, security toggles.
- [ ] `.github/workflows/ci.yml`: enforce contract tests and backend e2e gates.
- [ ] `README.md`: operator-facing API behavior and security defaults.
- [ ] `README.REMAINING.md`: progress/state tracking and release gates.

## Risk Register
- Risk: Refactor regressions in a large handler surface.
- Mitigation: behavior-preserving splits first, then feature changes.

- Risk: Hash migration can break existing key auth.
- Mitigation: dual-read migration window + test fixtures for legacy rows.

- Risk: Dashboard assumptions drift from API.
- Mitigation: integration tests for allowed routes + strict OpenAPI checks.

## Exit Criteria (Production)
- [ ] No spec/runtime drift.
- [ ] Security defaults enabled and tested.
- [ ] End-to-end API flows covered by automated tests.
- [ ] Dashboard integration passes against production-like API config.
- [ ] CI/CD required checks pass on `main` with branch protection enabled.
