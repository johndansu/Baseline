# Dashboard Backend Implementation Plan (CLI-Compliant, Auth-First)

## Purpose

Convert the current dashboard template into a production dashboard backed by Baseline API and policy engine, while preserving the auth-first model already implemented.

Primary goals:
- one backend logic path (no mock/template logic in runtime)
- strict parity with CLI policy outcomes and reports
- strong auth, RBAC, CSRF, and auditability for all dashboard actions

## Current Baseline

- Auth is implemented and working:
  - OIDC login/callback
  - session auth via backend cookie
  - API key auth for automation
- Core API resources are available:
  - projects, scans, policies, rulesets, api-keys, audit, integrations
- Dashboard template exists in `frontend-nodejs/public/dashboard.html` + `frontend-nodejs/public/js/dashboard.js`
- Template currently contains mock data and placeholder actions

## Non-Negotiable Rules

1. Dashboard never computes policy outcomes itself; backend does.
2. Dashboard scan and report outputs must match CLI outputs for same input.
3. All mutations require authn + authz + CSRF + audit event.
4. No secrets in frontend source, query params, or browser storage.
5. No alternate auth logic path; use current backend auth flow only.

## Scope

In scope:
- Backend APIs required by dashboard tabs
- Frontend wiring to real APIs
- RBAC enforcement and security hardening
- Testing, observability, and rollout

Out of scope:
- New policy semantics that differ from CLI
- Provider-specific browser auth SDK flows
- Non-essential cosmetic redesign

## Owner and Effort Legend

- Owners:
  - `BE`: Backend engineer
  - `FE`: Frontend engineer
  - `SEC`: Security engineer
  - `QA`: QA/test engineer
  - `SRE`: DevOps/SRE
- Effort:
  - `S`: 0.5-1 day
  - `M`: 2-3 days
  - `L`: 4-7 days
  - `XL`: 8+ days

## Phase 0: Contract and Template Cleanup

| ID | Task | Owner | Effort | Acceptance Criteria |
|---|---|---|---|---|
| P0-01 | Freeze dashboard API contract document (`/v1/dashboard/*` plus reused core endpoints). | BE | M | Contract reviewed and merged; all dashboard calls listed with request/response schemas and auth requirements. |
| P0-02 | Remove all mock data loading from `dashboard.js`. | FE | M | No hardcoded mock records rendered; all tabs show loading/empty states when API has no data. |
| P0-03 | Disable placeholder actions with no backend mapping. | FE | S | Buttons for non-implemented actions are hidden/disabled with explicit "Not implemented" message removed before release. |
| P0-04 | Add frontend API client module with shared fetch/auth/error handling. | FE | M | All dashboard network calls route through one client; unified error format handling (`code`, `message`, `request_id`). |

## Phase 1: Auth, Session, and RBAC Enforcement

| ID | Task | Owner | Effort | Acceptance Criteria |
|---|---|---|---|---|
| P1-01 | Protect dashboard routes/pages with backend session check (`/v1/auth/me`). | BE, FE | M | Unauthenticated users always redirect to `/signin.html`; authenticated users load dashboard without race conditions. |
| P1-02 | Implement role-based tab/action gating (viewer/operator/admin). | BE, FE | M | Unauthorized actions return `403`; frontend hides/disables controls based on capabilities endpoint. |
| P1-03 | Add `GET /v1/dashboard/capabilities` endpoint. | BE | S | Endpoint returns per-role feature flags consumed by frontend. |
| P1-04 | Enforce CSRF on all mutating dashboard API requests. | BE, FE | S | All POST/PUT/DELETE requests from dashboard include CSRF header and pass server validation. |
| P1-05 | Audit all mutating dashboard actions. | BE | M | Create/revoke keys, scans, project changes, integration updates all generate audit events with actor + request ID. |

## Phase 2: Read-Only Dashboard Data Wiring

| ID | Task | Owner | Effort | Acceptance Criteria |
|---|---|---|---|---|
| P2-01 | Implement `GET /v1/dashboard/overview` aggregate endpoint. | BE | M | Overview cards and charts use backend aggregates only (no frontend calculations beyond display transforms). |
| P2-02 | Implement `GET /v1/dashboard/activity` endpoint. | BE | M | Activity feed shows audit + scan events with pagination and filters. |
| P2-03 | Wire Scans tab to `/v1/scans` and scan detail/report routes. | FE | M | Scans table/detail fully driven by API; supports pagination, filter, and failure details. |
| P2-04 | Wire Policies tab to `/v1/policies` and version endpoints. | FE | M | Policy list/detail shows current status and version info directly from backend. |
| P2-05 | Wire Projects tab to `/v1/projects` read endpoints. | FE | M | Projects list/detail loads from API and handles empty/error states. |
| P2-06 | Wire API Keys tab to `/v1/api-keys` read endpoints. | FE | S | Key metadata list is real; no key material persisted in browser. |
| P2-07 | Wire Audit tab to `/v1/audit/events`. | FE | S | Audit table supports server-side pagination and filter query params. |

## Phase 3: Mutations and Operational Actions

| ID | Task | Owner | Effort | Acceptance Criteria |
|---|---|---|---|---|
| P3-01 | Add dashboard "Run Scan" workflow mapped to backend scan creation. | BE, FE | M | Run Scan from UI produces same backend scan objects as API/CLI path. |
| P3-02 | Add project create/update flows mapped to `/v1/projects`. | BE, FE | M | Project mutations succeed with RBAC checks and are reflected in audit log. |
| P3-03 | Add API key create/revoke flows with one-time key reveal UX. | BE, FE, SEC | M | New key value is shown once and never retrievable again; revoke reason captured and audited. |
| P3-04 | Add report download actions (`json`, `text`, `sarif`). | FE | S | Dashboard downloads are byte-equivalent in schema/content shape to CLI/API report output. |
| P3-05 | Remove localStorage "settings authority" behavior. | FE | S | Settings never act as system of record; backend state is authoritative. |

## Phase 4: Integrations and Background Processing Visibility

| ID | Task | Owner | Effort | Acceptance Criteria |
|---|---|---|---|---|
| P4-01 | Integrations tab wiring for webhook/check-run/status routes. | BE, FE | M | Integration forms submit to real endpoints; backend validation errors surfaced clearly. |
| P4-02 | Add integration job status endpoint (queue/retry/backoff visibility). | BE | M | UI can display last delivery status, retry count, next retry, and terminal failures. |
| P4-03 | Add admin-only integration secret update flow. | BE, SEC | M | Sensitive values accepted but never returned in clear; audit events emitted. |

## Phase 5: CLI Parity and Security Validation

| ID | Task | Owner | Effort | Acceptance Criteria |
|---|---|---|---|---|
| P5-01 | Build CLI parity test matrix for scan and policy outcomes. | QA, BE | L | For defined fixtures, dashboard-triggered outcomes match `baseline check/scan/report` outcomes. |
| P5-02 | Add authz test suite for each role against each dashboard endpoint/action. | QA, BE | M | Negative and positive authorization cases pass in CI. |
| P5-03 | Add CSRF/session expiry/refresh tests for dashboard mutation paths. | QA, BE | M | Session and CSRF protections validated by automated tests. |
| P5-04 | Add rate limiting tests for auth and dashboard APIs. | QA, BE | S | Rate limits trigger as configured without breaking normal usage. |
| P5-05 | Add secret scanning gate for frontend/backend dashboard files. | SEC, SRE | S | CI fails on hardcoded secrets; known false positives documented and handled. |

## Phase 6: Observability, Rollout, and Cutover

| ID | Task | Owner | Effort | Acceptance Criteria |
|---|---|---|---|---|
| P6-01 | Add metrics for dashboard endpoint latency, error rates, and auth failures. | BE, SRE | M | Prometheus metrics visible and alertable. |
| P6-02 | Add structured logs with request_id, actor, action, outcome for dashboard APIs. | BE | S | Logs support incident tracing for all dashboard mutations. |
| P6-03 | Define phased rollout toggles (read-only -> mutations -> integrations). | BE, SRE | S | Feature flags documented and tested in staging. |
| P6-04 | Run production-like smoke suite (`healthz`, `readyz`, auth flows, key flows, scans). | QA, SRE | M | Smoke suite green in CI and staging before merge/release. |
| P6-05 | Update README and operator runbook for new dashboard backend flow. | BE, FE | S | Docs reflect final routes, auth behavior, role requirements, and troubleshooting. |

## Template Feature Decision Matrix (Keep / Wire / Remove)

| Template Area | Decision | Backend Mapping |
|---|---|---|
| Overview cards/charts | Keep and wire | `GET /v1/dashboard/overview` |
| Activity feed | Keep and wire | `GET /v1/dashboard/activity` + audit data |
| Scans tab | Keep and wire | `/v1/scans` + `/v1/scans/{id}` + report route |
| Policies tab | Keep and wire | `/v1/policies`, versions, latest |
| Projects tab | Keep and wire | `/v1/projects` |
| API Keys tab | Keep and wire | `/v1/api-keys` |
| Integrations tab | Keep and wire | `/v1/integrations/*` + job status endpoint |
| Audit tab | Keep and wire | `/v1/audit/events` |
| Fake settings persistence | Remove | Replace with backend-backed settings metadata only |
| Fake connection tests | Remove | Replace with real health/status checks |
| Local backup/restore UI | Remove for now | Revisit only with backend support and security controls |

## Definition of Done (Dashboard Rebuild)

1. No mock data or template-only logic in runtime dashboard flow.
2. Every visible dashboard action maps to a real backend endpoint.
3. Policy/scan outcomes are CLI-consistent for identical input.
4. Auth, RBAC, CSRF, and audit controls are enforced for all mutations.
5. Required tests pass in CI (unit, integration, e2e, smoke, security).
6. Documentation and runbooks are updated and accurate.

## Execution Order Recommendation

1. Phase 0 + Phase 1 first (contract and security controls).
2. Phase 2 second (read-only real data).
3. Phase 3 third (mutations).
4. Phase 4 fourth (integrations).
5. Phase 5 and Phase 6 continuously, with final hard gate before release.
