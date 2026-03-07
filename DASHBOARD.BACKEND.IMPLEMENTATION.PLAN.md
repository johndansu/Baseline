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

## Implementation Update (2026-03-03)

Completed backend slice:
- Added `GET /v1/dashboard` route in API router.
- Implemented authenticated dashboard aggregate handler returning:
  - `metrics`
  - `recent_scans`
  - `top_violations`
  - `recent_events`
- Enforced auth on dashboard summary endpoint (`401` when missing/invalid credentials).
- Updated OpenAPI contract to include `/v1/dashboard` and related schemas.
- Added/updated tests:
  - dashboard summary auth + aggregate behavior tests
  - contract test assertions for dashboard response shape
  - full repo tests pass after this slice (`go test ./...`).

Completed backend slice (current):
- Added `GET /v1/dashboard/capabilities` route and handler.
- Added role/source-aware capability payload for dashboard gating:
  - `dashboard.view`
  - `projects.read|write`
  - `scans.read|run`
  - `api_keys.read|write`
  - `audit.read`
  - `integrations.read|write`
- Added auth and role-matrix tests for capabilities endpoint.
- Updated OpenAPI contract with capabilities path + schemas.
- Added contract response-shape assertion for capabilities endpoint.
- Added `GET /v1/dashboard/activity` route and handler.
- Implemented activity feed pagination and filters:
  - `limit`, `cursor`, `type`, `actor`, `from`, `to`
- Added ownership-scoped activity behavior for session/API-key principals.
- Updated OpenAPI contract and API contract shape tests for activity response.
- Added activity endpoint tests for auth requirement, pagination/filtering, and ownership scope.
- Wired dashboard Scans tab to real API endpoints:
  - `GET /v1/scans`
  - `GET /v1/projects` (project-name resolution)
  - `GET /v1/scans/{scan_id}/report?format=json|text|sarif` download links
- Added Scans UI filters (status/project), client-side pagination, and failure detail rendering.
- Wired dashboard Policies tab to real API endpoints:
  - `GET /v1/policies`
  - `GET /v1/policies/{name}/latest`
  - `GET /v1/policies/{name}/versions`
- Added policy table rendering for latest version, update time, version count, and backend links.
- Wired dashboard Projects tab to real API endpoints:
  - `GET /v1/projects`
  - `GET /v1/scans` (project posture/last-scan status enrichment)
- Added project table rendering for repository metadata, scan counts, latest scan time, and status badges.
- Wired dashboard API Keys tab to real API endpoint:
  - `GET /v1/api-keys`
- Added API key metadata rendering (id/prefix/role/source/status/created) with no key material exposure.
- Wired dashboard Audit tab to real API endpoint:
  - `GET /v1/audit/events`
- Added audit table rendering for event type, project, scan, timestamp, and normalized details.
- Removed remaining template-mode settings/integration loaders from runtime behavior.
- Disabled placeholder settings actions and blocked non-wired modal actions to prevent fake backend workflows.
- Wired Run Scan modal workflow to backend mutation path:
  - `GET /v1/projects` to populate project options
  - `POST /v1/scans` with CSRF header for session-authenticated mutation
  - refreshes overview and scans data after successful scan creation
- Wired Add Project modal workflow to backend mutation path:
  - `POST /v1/projects` with CSRF header for session-authenticated mutation
  - refreshes overview and projects data after successful project creation
- Wired Edit Project workflow to backend mutation path:
  - `PUT /v1/projects/{project_id}` with CSRF header for session-authenticated mutation
  - added backend audit event `project_updated`
  - added frontend row-level edit action and modal prefill from live project data
- Wired API key mutation workflows to backend paths:
  - `POST /v1/api-keys` from Generate Key modal with one-time key reveal modal
  - `DELETE /v1/api-keys/{key_id}` from Keys table revoke action with required reason/confirmation
  - supports production-style sensitive-action re-auth retry (`POST /v1/auth/reauth` + `X-Baseline-Reauth`)
  - refreshes overview, keys, and audit data after key lifecycle mutations
- Completed report download workflow hardening:
  - scans table report actions now trigger authenticated browser downloads via dashboard JS (no placeholder behavior)
  - backend report endpoint now returns attachment filenames via `Content-Disposition`
  - report formats now return explicit content types:
    - `application/json` for JSON
    - `text/plain` for text
    - `application/sarif+json` for SARIF
  - contract tests now verify response content-type and attachment filename behavior for all three formats
- Completed settings-authority cleanup:
  - settings form controls are now read-only/disabled in dashboard runtime
  - non-wired settings actions are disabled in UI (no placeholder mutation behavior)
  - only report generation remains active and maps to backend scan report endpoint
- Completed remaining placeholder-action cleanup:
  - disabled template-only header/actions (notifications, CLI quick-actions, non-backed profile links)
  - removed runtime toast path for blocked placeholder modals
  - replaced fake sign-out alert with real session sign-out (`DELETE /v1/auth/session`)
- Completed shared dashboard API client wiring:
  - added `frontend-nodejs/public/js/api-client.js` for centralized fetch/auth/error handling
  - dashboard now routes JSON and report download API calls through one client instance
  - unauthorized handling is centralized with consistent redirect behavior
  - sign-out now routes through dashboard client path instead of ad hoc fetch logic
- Completed role/capability-driven frontend gating:
  - dashboard bootstrap now loads `GET /v1/dashboard/capabilities` and applies server-driven permission state
  - unauthorized tabs are hidden from navigation and blocked by runtime tab-switch guard
  - mutating actions (add/edit project, run scan, generate/revoke API key) are blocked in UI without write capabilities
  - overview activity and audit API calls are gated behind `audit.read`
  - scan report generation is gated behind `scans.read`
  - role-aware user identity display now syncs after capabilities bootstrap
- Completed dashboard route/session gate hardening:
  - dashboard bootstrap now verifies authenticated backend session via `GET /v1/auth/me` before loading data
  - unauthenticated users are redirected to `/signin.html` with `return_to` target
  - removed direct Supabase auth scripts from `dashboard.html` to prevent dual-auth race/conflict on dashboard runtime
  - normalized auth-page redirects to `/dashboard` (instead of `/dashboard.html`) to match API-hosted dashboard route
- Completed CSRF enforcement hardening for dashboard mutations:
  - shared dashboard API client now auto-attaches `X-Baseline-CSRF: 1` for all mutating methods (`POST|PUT|PATCH|DELETE`)
  - per-endpoint CSRF header duplication removed from dashboard mutation handlers
  - sensitive-action headers (`X-Baseline-Confirm`, `X-Baseline-Reason`, `X-Baseline-Reauth`) remain explicit and intact
- Completed audit-context enforcement for mutating actions:
  - `AuditEvent` model now includes `actor` and `request_id`
  - dashboard mutation endpoints now emit request-scoped audit events with actor + request ID:
    - project create/update
    - scan create (including fail-path enforcement event)
    - API key issue/revoke
    - integration status publish (GitHub/GitLab)
  - dashboard activity feed now propagates audit event actor/request ID fields
  - SQLite store schema migrated to persist `audit_events.actor` and `audit_events.request_id` (schema version `5`)
  - added regression test coverage for actor/request_id propagation on project mutation events
- Completed integrations tab wiring to real mutation endpoints:
  - replaced integrations placeholder UI behavior with real submit workflows in dashboard runtime
  - wired GitHub publish form to `POST /v1/integrations/github/check-runs`
  - wired GitLab publish form to `POST /v1/integrations/gitlab/statuses`
  - integrated capability gating (`integrations.write`) for action enablement/disablement
  - surfaced backend validation/integration errors in form feedback (including `request_id` when available)
  - wired recent integrations activity view from `GET /v1/dashboard/activity?type=integration`
- Completed integration job status visibility endpoint and wiring:
  - added `GET /v1/integrations/jobs` endpoint with filters (`limit`, `provider`, `status`)
  - returns frontend-safe job summaries (no raw payload leakage)
  - includes queue state fields required for operational visibility:
    - `status`, `attempt_count`, `max_attempts`, `last_error`, `next_attempt_at`
  - wired integrations tab to display job queue table from `/v1/integrations/jobs`
  - added role and filter tests for integration jobs endpoint
  - updated OpenAPI and contract shape checks for the new route
- Completed admin-only integration secret update flow:
  - added `POST /v1/integrations/secrets` endpoint restricted to `admin` role
  - mutation path enforces CSRF for session-authenticated requests
  - accepts integration secret/config updates without echoing secret material in API responses
  - emits `integration_secrets_updated` audit event with request context
  - added coverage for role restrictions, validation failure, runtime update, and no-secret-echo behavior
  - updated OpenAPI and contract assertions for integration secrets update shape
- Started CLI parity validation matrix for Phase 5:
  - added `CLI.PARITY.TEST.MATRIX.md` with fixture-driven parity scenarios (`FX-01` to `FX-08`)
  - documented normalization/comparison rules to make CLI vs dashboard report checks deterministic
- Added first automated parity fixtures and CI gate coverage:
  - implemented `TestCLIDashboardParityMatrix` in `internal/api/cli_parity_matrix_test.go`
  - covers initial fixture set: `FX-01` (clean), `FX-02` (`D1`), `FX-06` (multi-violation)
  - validates normalized parity across JSON/text/SARIF report outputs and blocking-status semantics
  - wired explicit parity gate in CI (`.github/workflows/ci.yml`)
- Completed full parity fixture automation and CI gating:
  - expanded parity fixture coverage to include `FX-03`, `FX-04`, `FX-05`
  - added `FX-07` policy catalog parity test (`TestCLIDashboardParityPolicyCatalogFX07`)
  - added `FX-08` report format/content-type/content-disposition parity test (`TestCLIDashboardParityReportFormatsFX08`)
  - updated CI parity gate step to run all parity tests together
  - updated `CLI.PARITY.TEST.MATRIX.md` statuses to `DONE` for `FX-01` through `FX-08`
- Completed endpoint/action authz role matrix coverage:
  - added `TestReadEndpointsRBACMatrix` for dashboard/read endpoints across unauth/viewer/operator/admin
  - expanded `TestMutatingEndpointsRBACMatrix` to include:
    - `PUT /v1/projects/{project_id}` (project update action)
    - `POST /v1/integrations/secrets` (admin-only integration secret update action)
  - added `TestDashboardCapabilitiesAuthzFlagsMatchEndpointRBAC` to keep capability flags aligned with enforced RBAC
  - validated ownership-aware expectations (`404` for non-owner API-key detail/report access where applicable)
- Completed CSRF/session expiry/refresh mutation-path validation:
  - added `TestExpiredSessionBlocksMutationsUntilSessionRecreated` to verify:
    - expired session blocks dashboard mutations (`401`)
    - expired session is removed from active in-memory session map
    - mutation flow recovers after explicit session recreation
  - added `TestExpiredSensitiveReauthTokenRequiresRefreshForSessionMutation` to verify:
    - expired sensitive-action reauth token is rejected (`428 reauth_required`)
    - fresh reauth token enables the sensitive mutation path
  - retained existing CSRF guard coverage on session and admin mutation routes
- Completed rate limit validation for auth and dashboard APIs:
  - added `TestDashboardUnauthRequestsUseUnauthRateLimit` for unauthenticated dashboard route scope behavior
  - added `TestDashboardSessionRequestsUseGeneralRateLimit` for session-authenticated dashboard route scope behavior
  - added `TestAuthRateLimitScopeOverridesGeneralAndUnauthLimits` to verify auth-scope precedence
  - validated `429 rate_limited` responses with `Retry-After` behavior on capped paths
- Completed dashboard secret scanning CI gate:
  - added `scripts/secret-scan-dashboard.sh` to detect potential hardcoded secrets in `internal/api`, `frontend-nodejs/public`, and `frontend-nodejs/src`
  - wired gate into security CI workflow step (`.github/workflows/ci.yml`)
  - added explicit allowlist file (`security/secret-scan-allowlist.regex`) and operator guidance (`security/SECRET.SCAN.md`)
  - updated security checklist status to reference enforced secret scanning gate and allowlist process
- Completed frontend wiring cleanup to remove runtime template/mock paths:
  - removed template-disable runtime flow and "coming soon/not implemented" dashboard messaging
  - switched overview chart/quick-stats to backend-driven values (`/v1/dashboard`)
  - added active dashboard table search for current tab rows
  - converted header/dropdown actions to real routes/tabs (audit/API docs)
- Completed dashboard API observability metrics (`P6-01`):
  - added per-endpoint dashboard request counters by status class (`/v1/dashboard*`)
  - added dashboard request duration sum/count metrics for latency monitoring
  - added dashboard request error and auth-failure counters
  - added regression test coverage to validate `/metrics` includes dashboard observability series
- Completed structured mutation logging for dashboard APIs (`P6-02`):
  - added centralized `dashboard_mutation` structured log event for mutating API paths
  - included `request_id`, `actor`, `action`, `outcome`, `status`, `auth_source`, and `role` fields
  - added regression coverage to validate success/failure mutation logs include actor/action/outcome context
- Completed phased rollout toggles for dashboard mutations (`P6-03`):
  - added env-configurable rollout stage `BASELINE_API_DASHBOARD_ROLLOUT_STAGE`
  - supported stages: `read_only`, `mutations`, `integrations`, `full`
  - enforced runtime stage gates for mutation endpoint groups:
    - `core` mutations (`projects`, `scans`, `api-keys`, `policies`, `rulesets`)
    - `integrations` mutations (`/v1/integrations/*`)
  - added config parsing tests, rollout gate behavior tests, and `verify-prod` validation/warning coverage
- Completed production-like API smoke suite expansion (`P6-04`):
  - extended smoke scripts to validate authenticated identity endpoint flow (`/v1/auth/me`) for:
    - unauthenticated requests (`401`)
    - admin API key requests (`200`)
    - managed key requests (`200`) and revoked-key requests (`401`)
  - added API key lifecycle smoke coverage:
    - `POST /v1/api-keys` create
    - `DELETE /v1/api-keys/{key_id}` revoke with sensitive-action confirmation headers
    - post-revoke auth verification failure check
  - retained and validated health/readiness, project+scan creation, idempotent replay, report export, audit, and metrics checks
  - hardened smoke-run process lifecycle by building a temporary `baseline` binary per run and executing it directly (avoids stale `go run` child process behavior)
- Completed README and operator runbook alignment (`P6-05`):
  - updated README to reflect live dashboard backend endpoints (`/v1/dashboard`, `/v1/dashboard/capabilities`, `/v1/dashboard/activity`)
  - documented role requirements (`viewer|operator|admin`) and mutation security requirements (CSRF, confirmation, re-auth)
  - added dashboard/integration route coverage and rollout toggle docs (`BASELINE_API_DASHBOARD_ROLLOUT_STAGE`)
  - expanded operator quick-ops for dashboard/capabilities/activity probes and smoke-suite expectations
  - aligned `command.md` command text and API operator probes to current backend behavior

## Execution Status (as of 2026-03-07)

Status tags:
- `DONE`: implemented and validated
- `IN_PROGRESS`: partially implemented or documented but not complete
- `TODO`: not started

Phase 0:
- `P0-01` - `IN_PROGRESS`
- `P0-02` - `DONE`
- `P0-03` - `DONE`
- `P0-04` - `DONE`

Phase 1:
- `P1-01` - `DONE`
- `P1-02` - `DONE`
- `P1-03` - `DONE`
- `P1-04` - `DONE`
- `P1-05` - `DONE`

Phase 2:
- `P2-01` - `DONE`
- `P2-02` - `DONE`
- `P2-03` - `DONE`
- `P2-04` - `DONE`
- `P2-05` - `DONE`
- `P2-06` - `DONE`
- `P2-07` - `DONE`

Phase 3:
- `P3-01` - `DONE`
- `P3-02` - `DONE`
- `P3-03` - `DONE`
- `P3-04` - `DONE`
- `P3-05` - `DONE`

Phase 4:
- `P4-01` - `DONE`
- `P4-02` - `DONE`
- `P4-03` - `DONE`

Phase 5:
- `P5-01` - `DONE`
- `P5-02` - `DONE`
- `P5-03` - `DONE`
- `P5-04` - `DONE`
- `P5-05` - `DONE`

Phase 6:
- `P6-01` - `DONE`
- `P6-02` - `DONE`
- `P6-03` - `DONE`
- `P6-04` - `DONE`
- `P6-05` - `DONE`

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
| P2-01 | Implement `GET /v1/dashboard` aggregate endpoint. | BE | M | Overview cards and charts use backend aggregates only (no frontend calculations beyond display transforms). |
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
| Overview cards/charts | Keep and wire | `GET /v1/dashboard` |
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

## Next Implementation Slice (Immediate)

Goal for next slice:
- complete template fallback cleanup
- start mutation workflow wiring
- stabilize role-based frontend control gating

Target items:

Definition of completion for this slice:
1. Dashboard can render using only real backend data and capability flags.
2. Activity tab supports pagination/filter via backend query params.
3. Role-based control visibility is driven by backend capabilities, not hardcoded frontend role assumptions.
4. All related endpoints have authz tests and contract coverage.

## Endpoint Contract Detail

### `GET /v1/dashboard/capabilities`

Purpose:
- provide frontend-safe feature/action permissions for current principal

Auth:
- required (session or API key)

Response shape (example):

```json
{
  "role": "operator",
  "source": "session",
  "capabilities": {
    "dashboard.view": true,
    "projects.read": true,
    "projects.write": true,
    "scans.read": true,
    "scans.run": true,
    "api_keys.read": true,
    "api_keys.write": false,
    "audit.read": true,
    "integrations.read": true,
    "integrations.write": false
  }
}
```

Rules:
- capability map is additive and explicit
- frontend must not infer write permissions from role name
- backend remains source of truth; frontend gating is UX only

### `GET /v1/dashboard/activity`

Purpose:
- unified event feed for dashboard activity tab

Auth:
- required

Query params:
- `limit` (default 20, max 100)
- `cursor` (opaque pagination token)
- `type` (optional: `scan|audit|integration`)
- `actor` (optional)
- `from`, `to` (optional RFC3339)

Response shape (example):

```json
{
  "items": [
    {
      "id": "evt_01",
      "type": "scan",
      "action": "scan_completed",
      "status": "pass",
      "project_id": "proj_123",
      "actor": "user_abc",
      "created_at": "2026-03-05T19:00:00Z",
      "request_id": "req_123"
    }
  ],
  "next_cursor": "opaque_cursor_value"
}
```

Rules:
- newest first
- stable ordering for pagination
- do not expose sensitive payload fields (tokens, secrets, raw webhook signatures)

## Frontend Wiring Rules (Mandatory)

1. `dashboard.js` reads capabilities once at app bootstrap, then gates tabs/actions.
2. Every action button must map to one endpoint; no placeholder behavior.
3. No localStorage authority for role/capabilities/system state.
4. API error handling must use backend envelope only (`error.code`, `error.message`, `request_id` when present).
5. Unauthorized (`401`) redirects to signin; forbidden (`403`) shows role-appropriate message.

## Test Matrix for Next Slice

### Backend tests
- `capabilities` endpoint:
  - unauthenticated => `401`
  - viewer/operator/admin principal => expected capability map
- `activity` endpoint:
  - validates `limit` bounds and bad input (`400`)
  - returns cursor pagination deterministically
  - honors principal scope (no cross-owner leakage)

### Contract tests
- openapi schema includes both endpoints and response models
- contract fixtures validated for required/optional fields

### Frontend integration tests
- tab visibility and action state per capabilities response
- activity list pagination and filter query behavior
- no fallback to mock data when backend returns empty arrays

## Risk Register (Current)

1. Role drift between backend checks and frontend assumptions.
Mitigation: capability endpoint is sole frontend permission input.

2. Activity feed becomes expensive at scale.
Mitigation: index-backed queries + cursor pagination + bounded limits.

3. Template leftovers reintroduce fake actions.
Mitigation: hard delete placeholder code paths and block in PR review checklist.

## PR Checklist for Dashboard Backend Work

1. Endpoint added/changed in OpenAPI spec.
2. Authz tests added for viewer/operator/admin + unauthenticated.
3. No secrets/tokens returned in endpoint payloads.
4. Frontend consumes new endpoint via shared API client only.
5. `go test ./internal/api` and frontend tests pass.
6. `SECURITY.CHECKLIST.STATUS.md` updated if security posture changes.
