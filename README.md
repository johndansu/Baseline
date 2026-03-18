# Baseline

Baseline is a production-readiness gate for software delivery.

It provides:
- a CLI for deterministic policy checks before shipping
- an optional HTTP API for automation and operations
- dashboard backend endpoints for summary/capabilities/activity
- project-owned dashboard scan upload from the CLI
- auth frontend pages (`signin`, `signup`) for human login via OIDC (Supabase/Auth0 supported)

## Why Baseline

Most teams already have CI, tests, and deployment tooling, but release risk still slips through because the final safety checks are:
- spread across scripts and team tribal knowledge
- inconsistently enforced across repositories
- hard to audit after an incident

Baseline centralizes those release-readiness checks into deterministic rules and exposes them through:
- a CLI for local and CI usage
- an API for integrations and automation
- a human auth flow for operational access to API-backed functionality

In short: Baseline is not a replacement for CI/CD. It is a policy gate that sits in front of shipping.

## What Baseline Does

Baseline helps teams block risky releases before they reach production by enforcing checks such as:
- CI coverage and PR enforcement
- secret detection
- dependency and deployment hygiene
- documentation/rollback/readiness requirements
- unsafe code pattern detection

Baseline is deterministic:
- AI can assist with scaffold generation (`baseline generate`, `baseline pr`)
- AI does not decide policy outcomes

## Typical Usage Patterns

### 1) CLI in CI/CD (most common)

Use `baseline check` or `baseline enforce` in pull request and release pipelines to block merges/releases when policy requirements are not met.

### 2) API for Automation / Integrations

Use `baseline api serve` when you need:
- API key management
- scan ingestion/report retrieval
- audit event retrieval
- webhook ingestion for GitHub/GitLab signals

### 3) Human Login for Operations

Use the API-hosted auth pages (`/signin.html`, `/signup.html`) to authenticate via OIDC (Supabase/Auth0), then let Baseline issue a local session cookie for subsequent API requests.

## Current Project Status (Important)

Supported now:
- CLI checks and reports
- project-local dashboard upload connection for `baseline scan`
- HTTP API (`baseline api serve`)
- API key auth
- OIDC login for humans (Supabase/Auth0)
- Baseline session cookie auth (`/v1/auth/session`)
- dashboard backend endpoints:
  - `GET /v1/dashboard`
  - `GET /v1/dashboard/capabilities`
  - `GET /v1/dashboard/activity`
- Auth frontend pages at `http://127.0.0.1:8080/signin.html` and `http://127.0.0.1:8080/signup.html`
- dashboard proxy service via `baseline dashboard`

## Repository Overview

- `cmd/baseline` - CLI entrypoint
- `internal/policy` - deterministic policy evaluation
- `internal/api` - HTTP API server, auth, persistence, integrations
- `internal/ai` - AI-assisted scaffolding helpers
- `frontend/` - API-hosted landing + auth pages (`index.html`, `signin.html`, `signup.html`)
- `frontend-nodejs/public/` - dashboard template frontend (`dashboard.html`, JS modules)
- `scripts/` - smoke tests, release gates, operational scripts

## Requirements

- Go `1.26.1+` (see `go.mod`)
- Git in `PATH`
- Optional:
  - Ollama or OpenRouter (for AI scaffold commands)
  - GitHub CLI (`gh`) for `baseline pr`

## Build

```bash
go build -o baseline.exe ./cmd/baseline
```

## Release Packaging

Generate versioned release artifacts and checksums locally:

```powershell
.\scripts\package-release.ps1
```

```bash
bash ./scripts/package-release.sh
```

Artifacts are written under `.artifacts/release/<timestamp>` and include:
- raw platform-specific binaries under `binaries/`
- distributable archives under `archives/`
- `SHA256SUMS.binaries`
- `SHA256SUMS.archives`
- build metadata and release info

## Quick Start

### 1) CLI-only usage (no API)

```bash
baseline check
baseline enforce
baseline scan
baseline report --text
```

If you later connect the current project to the dashboard, plain `baseline scan` can also upload results automatically for that project.

### 2) API + auth pages (recommended current flow)

Start the API:

```bash
baseline api serve --addr :8080
```

Open:
- `http://127.0.0.1:8080/` (landing page)
- `http://127.0.0.1:8080/signin.html`
- `http://127.0.0.1:8080/signup.html`

Optional dashboard proxy (read-only proxy for selected API endpoints):

```bash
baseline dashboard serve --addr 127.0.0.1:8091 --api http://127.0.0.1:8080
```

Open:
- `http://127.0.0.1:8091/`

If using OIDC (Supabase/Auth0), configure the env vars in the `Supabase Auth` or `Auth0` sections below first.

### 3) Minimal local API smoke (manual)

After starting the API, you can quickly verify it is alive:

```bash
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/readyz
curl http://127.0.0.1:8080/metrics
```

## CLI Commands

### Core

- `baseline version` - print version/build information
- `baseline check` - run all policy checks; exits non-zero on blocking violations
- `baseline enforce` - enforcement-focused output for CI/CD
- `baseline scan` - produce scan summary (files/security/violations); can also upload to the dashboard using a saved project connection
- `baseline init` - create `.baseline/config.yaml`
- `baseline report` - output reports (`--text`, `--json`, `--sarif`)
- `baseline explain <policy_id>` - explain policy status + remediation

### AI-Assisted (Scaffolding Only)

- `baseline generate` - generate scaffolded fixes from detected violations
- `baseline pr` - generate fixes, commit/push branch, attempt `gh pr create`

### API / Operations

- `baseline api serve` - run HTTP API server
- `baseline api keygen` - generate random API key
- `baseline api verify-prod [--strict]` - validate API production env config
- `baseline dashboard serve` - local dashboard proxy service for selected read APIs
- `baseline dashboard connect` - connect the current repository to a dashboard project using a user-owned API key
- `baseline dashboard status` - show the saved dashboard connection for the current repository
- `baseline dashboard disconnect` - remove the saved dashboard connection for the current repository

For a concise command list, see `command.md`.

### CLI Dashboard Upload Flow

Baseline supports a project-local dashboard upload flow for `baseline scan`.

Recommended setup:

1. Sign into the dashboard.
2. Generate a personal API key from the dashboard.
3. Run `baseline scan`.
4. On first use, choose whether the current repository should upload scan results to the dashboard.
5. If enabled, provide:
   - dashboard API base URL
   - personal API key

Baseline then:

- resolves or creates the dashboard project for the current repository
- stores project-local connection metadata in `.baseline/config.yaml`
- stores the local API key in `.baseline/secrets.json`
- uses that saved connection for future `baseline scan` runs

Notes:

- `.baseline/secrets.json` is local-only and gitignored
- explicit flags (`--api`, `--project-id`, `--api-key`) still work and override saved project connection settings
- if a saved dashboard connection becomes invalid, `baseline scan` tells you to run `baseline dashboard connect` to repair it

## Exit Codes

- `0` success
- `20` blocking violations
- `50` system/runtime error

## Policy Checks Enforced

Baseline currently evaluates these checks (IDs from `internal/types/types.go`):

- `A1` primary branch protection (PR-required + direct push restrictions)
- `B1` CI workflows run on PRs and execute tests
- `C1` automated tests exist
- `D1` no plaintext secrets/token patterns in scannable files
- `E1` dependency management files exist
- `F1` README + license requirements are met
- `G1` risky code patterns blocked (unsafe pointer, unsafe exec/eval/system, SQL string building)
- `H1` deployment config exists; Dockerfile non-root `USER` enforced
- `I1` infrastructure-as-code artifacts exist
- `J1` env template exists (`.env.example` / `.env.template`)
- `K1` backup/recovery docs or scripts exist
- `L1` logging/monitoring config or docs exist
- `R1` rollback documentation exists

Notes:
- most violations are `block`
- Dockerfile `:latest` usage is currently reported as `warn`

## API Server

Start:

```bash
baseline api serve --addr :8080
```

Other API subcommands:

```bash
baseline api keygen
baseline api verify-prod
baseline api verify-prod --strict
```

### Auth Model (Current)

Baseline supports two auth categories:

1. Human auth (recommended)
- OIDC login via `/v1/auth/oidc/login` and `/v1/auth/oidc/callback`
- provider examples: Supabase, Auth0
- Baseline issues its own session cookie after successful OIDC callback
- session status/identity via `GET /v1/auth/me`

2. Machine auth (automation/CI/scripts)
- API key auth via `Authorization: Bearer <key>`

Also supported:
- optional self-service API key registration via `/v1/auth/register` (if enabled)
- API key lifecycle management via `/v1/api-keys` (admin required for create/revoke)

Security behavior:
- session-authenticated mutating requests require `X-Baseline-CSRF: 1`
- strict sensitive-action re-auth is enabled by default in production startup mode, and can also be forced in any mode via `BASELINE_API_SENSITIVE_ACTION_REAUTH_ENABLED=true`; this requires `POST /v1/auth/reauth` and `X-Baseline-Reauth` on destructive operations
- sensitive destructive actions (for example `DELETE /v1/api-keys/{id}`) require:
  - `X-Baseline-Confirm: revoke_api_key`
  - `X-Baseline-Reason: <reason>`
- API keys and audit events persist in SQLite (`BASELINE_API_DB_PATH`)
- webhook ingestion can persist integration jobs in SQLite with retry/backoff worker processing

### Human Auth Flow (OIDC -> Baseline Session)

This is the supported human-login flow today:

1. User opens `http://127.0.0.1:8080/signin.html` or `http://127.0.0.1:8080/signup.html`
2. Frontend redirects to `GET /v1/auth/oidc/login`
3. Baseline redirects to your OIDC provider (Supabase/Auth0)
4. User authenticates with the provider
5. Provider redirects back to `GET /v1/auth/oidc/callback`
6. Baseline validates the OIDC response and creates a local session cookie
7. Client calls `GET /v1/auth/me` to confirm authenticated identity/session

Why this design matters:
- the browser does not need to manage provider-specific auth logic directly
- Baseline can apply one consistent auth model for API access (session cookie or API key)
- API authorization stays centralized in your backend

### Database Requirement

CLI-only usage:
- no database required

API usage:
- SQLite is recommended and already supported
- required for persistent API keys, audit events, and integration job queues

Use:
- `BASELINE_API_DB_PATH=<path-to-sqlite-db>`

Recommended local example:

```bash
BASELINE_API_DB_PATH=.baseline/baseline.db
```

CLI dashboard upload storage:

- `.baseline/config.yaml` keeps non-secret project connection metadata
- `.baseline/secrets.json` keeps the local dashboard API key and is not committed

### Implemented HTTP Routes (Current)

#### UI/Auth Page Routes (API-hosted)

- `GET /` (landing page)
- `GET /index.html`
- `GET /signin` and `GET /signin.html`
- `GET /signup` and `GET /signup.html`
- `GET /styles.css`
- `GET /app.js`
- `GET /auth.js`
- `GET /assets/baseline-logo.png`
- `GET /img/baseline logo.png`
- `GET /img/baseline favicon.png`

#### Operational Routes

- `GET /openapi.yaml`
- `GET /metrics`
- `GET /healthz` and `GET /livez`
- `GET /readyz`

#### Auth Routes

- `GET /v1/auth/me`
- `GET /v1/auth/oidc/login`
- `GET /v1/auth/oidc/callback`
- `POST /v1/auth/reauth`
- `POST|GET|DELETE /v1/auth/session`
- `POST /v1/auth/register`

#### API Key Routes

- `GET|POST /v1/api-keys`
- `DELETE /v1/api-keys/{key_id}`

#### Integrations

- `GET /v1/integrations/jobs`
- `POST /v1/integrations/secrets` (admin)
- `POST /v1/integrations/github/webhook`
- `POST /v1/integrations/gitlab/webhook`
- `POST /v1/integrations/github/check-runs`
- `POST /v1/integrations/gitlab/statuses`

#### Dashboard Backend Endpoints

- `GET /v1/dashboard`
- `GET /v1/dashboard/capabilities`
- `GET /v1/dashboard/activity`

#### Core API Resources

- `GET|POST /v1/projects`
- `GET /v1/projects/{project_id}`
- `GET|POST /v1/scans`
- `GET /v1/scans/{scan_id}`
- `GET /v1/scans/{scan_id}/report?format=json|text|sarif`
- `GET /v1/policies`
- `GET|POST /v1/policies/{name}/versions`
- `GET /v1/policies/{name}/latest`
- `POST /v1/rulesets`
- `GET /v1/rulesets/latest`
- `GET /v1/rulesets/{version}`
- `GET /v1/audit/events`

## API Environment Variables

Env files auto-load in this order:
- `BASELINE_API_ENV_FILE` (if set)
- `.env.production`
- `.env`
- `api.env`

### Core Server

- `BASELINE_API_ENV_FILE`
- `BASELINE_API_ADDR`
- `BASELINE_API_DB_PATH`
- `BASELINE_API_TIMEOUT_MS`
- `BASELINE_API_IDLE_TIMEOUT_MS`
- `BASELINE_API_MAX_BODY_BYTES`
- `BASELINE_API_SHUTDOWN_TIMEOUT_MS`

### API Key Auth

- `BASELINE_API_KEY`
- `BASELINE_API_KEYS`
- `BASELINE_API_KEY_HASH_SECRET`

### Transport / Proxy / CORS

- `BASELINE_API_REQUIRE_HTTPS`
- `BASELINE_API_CORS_ALLOWED_ORIGINS`
- `BASELINE_API_TRUST_PROXY_HEADERS`

### Session / Dashboard-Auth Compatibility Settings

- `BASELINE_API_DASHBOARD_SESSION_ENABLED`
- `BASELINE_API_DASHBOARD_SESSION_ROLE`
- `BASELINE_API_DASHBOARD_SESSION_TTL_MINUTES`
- `BASELINE_API_DASHBOARD_SESSION_COOKIE_SECURE`
- `BASELINE_API_DASHBOARD_AUTH_PROXY_ENABLED`
- `BASELINE_API_DASHBOARD_AUTH_PROXY_USER_HEADER`
- `BASELINE_API_DASHBOARD_AUTH_PROXY_ROLE_HEADER`
- `BASELINE_API_DASHBOARD_ROLLOUT_STAGE` (`read_only|mutations|integrations|full`)

### Self-Service API Key Enrollment

- `BASELINE_API_SELF_SERVICE_ENABLED`
- `BASELINE_API_ENROLLMENT_TOKENS`
- `BASELINE_API_ENROLLMENT_TOKEN_TTL_MINUTES`
- `BASELINE_API_ENROLLMENT_TOKEN_MAX_USES`

### OIDC (Generic)

- `BASELINE_API_OIDC_ENABLED`
- `BASELINE_API_OIDC_ISSUER_URL`
- `BASELINE_API_OIDC_CLIENT_ID`
- `BASELINE_API_OIDC_CLIENT_SECRET`
- `BASELINE_API_OIDC_REDIRECT_URL`
- `BASELINE_API_OIDC_SCOPES`
- `BASELINE_API_OIDC_ALLOWED_EMAIL_DOMAINS`
- `BASELINE_API_OIDC_REQUIRE_VERIFIED_EMAIL`
- `BASELINE_API_OIDC_DEFAULT_ROLE`

### Auth0 Aliases (map to OIDC)

- `BASELINE_API_AUTH0_ENABLED`
- `BASELINE_API_AUTH0_DOMAIN`
- `BASELINE_API_AUTH0_CLIENT_ID`
- `BASELINE_API_AUTH0_CLIENT_SECRET`
- `BASELINE_API_AUTH0_CALLBACK_URL`
- `BASELINE_API_AUTH0_SCOPES`
- `BASELINE_API_AUTH0_ALLOWED_EMAIL_DOMAINS`
- `BASELINE_API_AUTH0_REQUIRE_VERIFIED_EMAIL`
- `BASELINE_API_AUTH0_DEFAULT_ROLE`

### Supabase Aliases (map to OIDC)

- `BASELINE_API_SUPABASE_ENABLED`
- `BASELINE_API_SUPABASE_URL` (normalized to `/auth/v1`)
- `BASELINE_API_SUPABASE_ISSUER_URL`
- `BASELINE_API_SUPABASE_CLIENT_ID`
- `BASELINE_API_SUPABASE_CLIENT_SECRET`
- `BASELINE_API_SUPABASE_CALLBACK_URL`
- `BASELINE_API_SUPABASE_SCOPES`
- `BASELINE_API_SUPABASE_ALLOWED_EMAIL_DOMAINS`
- `BASELINE_API_SUPABASE_REQUIRE_VERIFIED_EMAIL`
- `BASELINE_API_SUPABASE_DEFAULT_ROLE`

### Integrations

- `BASELINE_API_GITHUB_WEBHOOK_SECRET`
- `BASELINE_API_GITLAB_WEBHOOK_TOKEN`
- `BASELINE_API_GITHUB_TOKEN`
- `BASELINE_API_GITHUB_API_URL`
- `BASELINE_API_GITLAB_TOKEN`
- `BASELINE_API_GITLAB_API_URL`

### Rate Limiting / AI Flags

- `BASELINE_API_RATE_LIMIT_ENABLED`
- `BASELINE_API_RATE_LIMIT_REQUESTS`
- `BASELINE_API_RATE_LIMIT_WINDOW_SECONDS`
- `BASELINE_API_AUTH_RATE_LIMIT_REQUESTS`
- `BASELINE_API_AUTH_RATE_LIMIT_WINDOW_SECONDS`
- `BASELINE_API_UNAUTH_RATE_LIMIT_REQUESTS`
- `BASELINE_API_UNAUTH_RATE_LIMIT_WINDOW_SECONDS`
- `BASELINE_API_SENSITIVE_ACTION_REAUTH_ENABLED`
- `BASELINE_API_AI_ENABLED`

For managed API key rotation, use `scripts/api-key-rotate.ps1`.

### Role Requirements (API)

- `viewer`: read endpoints only (`/v1/dashboard*`, projects/scans/policies/rulesets/audit reads)
- `operator`: viewer + standard mutations (project create/update, scan create)
- `admin`: operator + admin-sensitive mutations (API key create/revoke, integration secret updates)

Notes:
- session mutations require `X-Baseline-CSRF: 1`
- sensitive operations (for example key revocation) also require confirm/reason headers and may require `POST /v1/auth/reauth` + `X-Baseline-Reauth`

## Supabase Auth (Recommended Human Login)

Baseline uses Supabase as an OIDC provider through the backend.

Important:
- do not use Supabase `anon` or `service_role` keys for OIDC client credentials
- use OIDC client credentials (client ID / client secret)

Set:

```bash
BASELINE_API_SUPABASE_ENABLED=true
BASELINE_API_SUPABASE_URL=https://<project-ref>.supabase.co
BASELINE_API_SUPABASE_CLIENT_ID=<oidc_client_id>
BASELINE_API_SUPABASE_CLIENT_SECRET=<oidc_client_secret>
BASELINE_API_SUPABASE_CALLBACK_URL=http://127.0.0.1:8080/v1/auth/oidc/callback
BASELINE_API_SUPABASE_DEFAULT_ROLE=operator
BASELINE_API_DASHBOARD_SESSION_ENABLED=true
```

Supabase-side configuration (OIDC/provider setup):
- callback / redirect URL: `http://127.0.0.1:8080/v1/auth/oidc/callback`
- allow your local/API origin as required by your Supabase auth config

Auth page flow:
- `frontend/signin.html` -> `/v1/auth/oidc/login`
- `frontend/signup.html` -> `/v1/auth/oidc/login?mode=signup`

Result:
- Baseline creates a local session cookie after OIDC callback

### Supabase Setup Checklist (Local)

Use this checklist when login/signup fails:

1. Confirm API is running on `http://127.0.0.1:8080`
2. Confirm callback URL matches exactly:
   - `http://127.0.0.1:8080/v1/auth/oidc/callback`
3. Confirm you used OIDC client credentials:
   - `BASELINE_API_SUPABASE_CLIENT_ID`
   - `BASELINE_API_SUPABASE_CLIENT_SECRET`
   - not Supabase `anon` or `service_role` keys
4. Open the API-hosted auth pages (not a generic static server):
   - `http://127.0.0.1:8080/signin.html`
   - `http://127.0.0.1:8080/signup.html`
5. Verify the backend login route responds (redirect/302 expected when OIDC is enabled):

```bash
curl -i "http://127.0.0.1:8080/v1/auth/oidc/login?return_to=%2F"
```

Expected:
- `302 Found` to your provider (good)
- `403 oidc_disabled` (OIDC config not enabled)
- not `404`

## Auth0 (Optional Alternative)

Auth0 aliases are still supported if you prefer it:
- `BASELINE_API_AUTH0_*` maps to the same OIDC backend flow

## Auth Frontend Pages (Current)

The frontend currently focuses on auth-first flows:

- `frontend/index.html` - landing page
- `frontend/signin.html` - sign-in page (redirects to backend OIDC login)
- `frontend/signup.html` - sign-up page (redirects to backend OIDC signup/login flow)
- `frontend/auth.js` - auth-page logic and session status helpers

Supported testing path:
- run API on `:8080`
- open API-hosted pages, not a generic static server

Recommended URLs:
- `http://127.0.0.1:8080/`
- `http://127.0.0.1:8080/signin.html`
- `http://127.0.0.1:8080/signup.html`

### Important Local Dev Note

If you open `frontend/signin.html` directly from a generic static server (for example `python -m http.server` or VS Code Live Server), auth may fail because:
- `/v1/auth/oidc/login` exists on the Baseline API server, not your static file server
- the browser may send auth requests to the wrong origin and return `404`

Use API-hosted pages on `:8080` for real auth testing.

## Operator Runbook (Quick Ops)

1. Start the API:

```bash
baseline api serve --addr :8080
```

2. Liveness/readiness:

```bash
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/readyz
```

3. Metrics:

```bash
curl http://127.0.0.1:8080/metrics
```

4. Verify auth-protected API access:

```bash
curl -H "Authorization: Bearer <admin_key>" http://127.0.0.1:8080/v1/dashboard
```

5. Verify capability payload and activity feed:

```bash
curl -H "Authorization: Bearer <admin_key>" \
  "http://127.0.0.1:8080/v1/dashboard/capabilities"
curl -H "Authorization: Bearer <admin_key>" \
  "http://127.0.0.1:8080/v1/dashboard/activity?limit=10"
```

6. Inspect audit trail:

```bash
curl -H "Authorization: Bearer <admin_key>" \
  "http://127.0.0.1:8080/v1/audit/events?limit=20"
```

7. Rotate/revoke managed API keys (Windows PowerShell):

```powershell
.\scripts\api-key-rotate.ps1 `
  -ApiBaseUrl http://127.0.0.1:8080 `
  -AdminApiKey "<admin_key>" `
  -Role operator `
  -Name "ops-rotation-01" `
  -RevokeKeyId "<old_key_id>"
```

8. Production preflight:

```bash
baseline api verify-prod --strict
bash ./scripts/release-gate.sh
bash ./scripts/api-smoke.sh
```

Windows PowerShell:

```powershell
.\scripts\release-gate.ps1
.\scripts\api-smoke.ps1
```

Artifacts are written under `.artifacts/api-smoke/<timestamp>`.

Smoke suite coverage now includes:
- health and readiness
- auth identity (`/v1/auth/me`) unauth/auth/revoked-key checks
- API key lifecycle create/revoke flow
- project and scan creation (including idempotent replay)
- report export, audit, and metrics checks

## GitHub Branch Protection (Required)

For `main`, enforce:
- pull requests required before merge
- direct pushes restricted
- force pushes disabled
- required checks:
  - `Test`
  - `Security Scan`
  - `Release Gates`
  - `API Smoke`

## Frontend Static Mode

For UI preview only (no supported auth flow):
- open `frontend/index.html`

Notes:
- auth works reliably when served by Baseline API (`:8080`)
- generic static servers often cause wrong-origin auth requests and 404s

## Troubleshooting (Common Issues)

### OIDC login returns `404`

Usually means the browser is calling the wrong origin.

Check:
- Are you opening `http://127.0.0.1:8080/signin.html` (correct) or a static server URL like `http://localhost:8000/...` (wrong for auth)?
- Is the Baseline API actually running on `:8080`?

### OIDC login returns `403 oidc_disabled`

OIDC is not enabled/configured.

Set at minimum:
- `BASELINE_API_OIDC_ENABLED=true` (or provider alias like `BASELINE_API_SUPABASE_ENABLED=true`)
- issuer URL
- client ID
- client secret
- redirect URL

### OIDC callback fails after provider login

Most common causes:
- redirect URL mismatch (`localhost` vs `127.0.0.1`)
- wrong client credentials
- provider-side callback/allowed origin not configured

### API requests fail after successful login

Check:
- `GET /v1/auth/me` returns authenticated session info
- session cookie is present
- mutating requests include `X-Baseline-CSRF: 1`
- API key revoke requests include `X-Baseline-Confirm` and `X-Baseline-Reason`

### Dashboard API returns `403 forbidden`

Likely role/capability mismatch.

Check:
- `GET /v1/dashboard/capabilities` for the current principal
- whether your action requires `operator` or `admin`

### Sensitive action returns `428 reauth_required`

Required step-up auth token is missing/expired.

Fix:
- call `POST /v1/auth/reauth`
- retry with `X-Baseline-Reauth: <token>`
- include `X-Baseline-Confirm` and `X-Baseline-Reason` where required

### Mutation returns `503 rollout_blocked`

Dashboard rollout stage is restricting writes.

Check:
- `BASELINE_API_DASHBOARD_ROLLOUT_STAGE`
- allowed values: `read_only`, `mutations`, `integrations`, `full`

## Example API Usage

### Create a project (API key auth)

```bash
curl -X POST http://127.0.0.1:8080/v1/projects \
  -H "Authorization: Bearer <admin_or_operator_key>" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"payments-service\",\"default_branch\":\"main\"}"
```

### List projects

```bash
curl http://127.0.0.1:8080/v1/projects \
  -H "Authorization: Bearer <viewer_or_higher_key>"
```

### Fetch current auth identity/session (human login)

```bash
curl http://127.0.0.1:8080/v1/auth/me
```

Assets used:
- `frontend/styles.css`
- `frontend/app.js`
- `frontend/auth.js`
- `img/baseline logo.png`

## AI Scaffolding

Baseline uses AI only for scaffolding/remediation suggestions.

- `baseline generate` can create CI/test/README/Dockerfile/env-template scaffolds from violations
- `baseline pr` can generate files, commit/push a branch, and attempt PR creation

Provider configuration:
- `AI_PROVIDER=ollama` with `OLLAMA_URL` and optional `OLLAMA_MODEL`
- `AI_PROVIDER=openrouter` (or set `OPENROUTER_API_KEY`) with `OPENROUTER_API_KEY`, optional `OPENROUTER_MODEL`, optional `OPENROUTER_URL`
- fallback: if provider is `ollama` and `OPENROUTER_API_KEY` is set, Baseline may fall back to OpenRouter when Ollama checks/requests fail
- optional env file auto-load for AI commands: `BASELINE_AI_ENV_FILE`, `.env.production`, `.env`, `ai.env`, `api.env`

AI is not used to decide enforcement outcomes. Review generated content before merge.

## Testing

```bash
go test ./...
```

## Release Integrity

Release artifacts are hardened in CI:

- `SHA256SUMS` generated for release binaries
- binaries and checksums keylessly signed with Sigstore Cosign
- signatures (`.sig`) and certificates (`.pem`) uploaded with release assets

## Security

See `SECURITY.md` for vulnerability reporting.

## License

MIT License (`LICENSE`).
