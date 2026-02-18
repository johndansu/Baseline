# Changelog

All notable changes to this project are documented in this file.

## [Unreleased] - 2026-02-18

### Highlights
- Moved the API from mostly in-memory behavior toward a durable service model.
- Added first-class API key lifecycle management (issue/list/revoke).
- Added OpenAPI contract publishing at runtime.
- Added signed inbound integration webhooks for GitHub and GitLab.
- Hardened auth/session behavior for production use.

### Added
- API key management endpoints:
  - `GET /v1/api-keys` returns metadata inventory (no raw secrets).
  - `POST /v1/api-keys` issues a new key (admin only, one-time secret return).
  - `DELETE /v1/api-keys/{id}` revokes an existing managed key (admin only).
- OpenAPI route:
  - `GET /openapi.yaml` serves the API contract.
- Integration webhook routes:
  - `POST /v1/integrations/github/webhook`
  - `POST /v1/integrations/gitlab/webhook`
- SQLite persistence layer:
  - New persistent store implementation for API keys and audit events.
  - Database initialization/migrations on API startup.
  - Write-ahead logging and busy timeout pragmas for safer local concurrency.
- Additional API metadata model:
  - `APIKeyMetadata` includes `id`, `name`, `role`, `prefix`, `source`, `created_at`, `created_by`, `revoked`, `revoked_at`.
- New configuration/env support:
  - `BASELINE_API_REQUIRE_HTTPS`
  - `BASELINE_API_DASHBOARD_SESSION_COOKIE_SECURE`
  - `BASELINE_API_GITHUB_WEBHOOK_SECRET`
  - `BASELINE_API_GITLAB_WEBHOOK_TOKEN`

### Security
- Added Bearer auth challenge headers:
  - 401 responses now include `WWW-Authenticate: Bearer ...` for standards-compliant clients.
- Added CSRF guard for session-cookie auth:
  - Session-authenticated mutating requests now require `X-Baseline-CSRF: 1`.
- Enforced stricter request parsing:
  - Max request body size at handler level.
  - Strict JSON decode behavior with unknown-field rejection.
  - Deterministic `request_too_large` error on overflow.
- Hardened session cookies:
  - `HttpOnly` + strict same-site behavior.
  - secure-cookie behavior aligned with HTTPS/proxy settings.
- GitHub webhook signature verification:
  - HMAC SHA-256 via `X-Hub-Signature-256` validated against configured secret.
- GitLab webhook token verification:
  - `X-Gitlab-Token` validated with constant-time compare.

### Changed
- Self-service registration (`/v1/auth/register`) now issues server-generated API keys.
- API key auth now supports full lifecycle states:
  - active, revoked, bootstrap-protected.
- Bootstrap key behavior:
  - keys injected from environment are tracked as `source=bootstrap`.
  - bootstrap keys are intentionally not revocable via API (must rotate in env + restart).
- API startup behavior:
  - `baseline api serve` now opens a persistent SQLite store and restores state.
  - No-arg `baseline` auto-starts API when key config is present.
- Dashboard behavior:
  - removed persistent API-key storage in browser `localStorage`.
  - credential entry remains in-memory for active session only.
- Documentation:
  - README and OpenAPI contract updated to reflect current implemented routes and security requirements.

### Persistence
- API keys persisted to SQLite with metadata and revocation state.
- Audit events persisted and loaded across restarts.
- Startup reconciliation:
  - bootstrap env keys are ensured in DB without overwriting managed records.
  - persisted managed keys are loaded into runtime auth state.
- Revocation durability:
  - key revocation is persisted before in-memory invalidation is finalized.

### API Contract and Runtime Behavior
- Added explicit webhook contract entries to OpenAPI.
- Added API key lifecycle contract entries to OpenAPI.
- Error behavior standardized across new endpoints:
  - `401 unauthorized`
  - `403 forbidden` / `integration_disabled`
  - `404 not_found`
  - `409 conflict` for bootstrap key revoke attempts
  - `413 request_too_large`

### CLI and Ops
- API serve flow now fails early with deterministic error when store open fails.
- Production verification now flags placeholder webhook secrets/tokens.
- API usage/help text expanded with new integration env vars.

### Tests
- Added/expanded coverage for:
  - unauthorized Bearer challenge behavior
  - CSRF enforcement paths
  - server-generated self-service keys
  - API key lifecycle (create/list/revoke/blocked bootstrap revoke)
  - persistence across restart (key auth + revoke + audit events)
  - webhook validation (GitHub signature, GitLab token)
  - config parsing for new security/integration env variables
- Full suite passing after these changes.

### Fixes
- Fixed restart/state issues caused by config map aliasing.
- Fixed key state reclassification edge cases during persistence bootstrap.
- Fixed lifecycle consistency so revoked keys are rejected after restart.

### Notes for Operators
- If you use session cookie auth for mutating calls, include `X-Baseline-CSRF: 1`.
- For webhook ingestion, configure one or both:
  - `BASELINE_API_GITHUB_WEBHOOK_SECRET`
  - `BASELINE_API_GITLAB_WEBHOOK_TOKEN`
- Keep `BASELINE_API_DB_PATH` on persistent storage in production.
- Rotate any previously exposed API secrets before deploying these changes.
