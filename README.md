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

## Postgres Store Test Runbook

Run the focused Postgres-backed store tests against a disposable local container:

Windows PowerShell:

```powershell
.\scripts\test-postgres-store.ps1
```

Linux/macOS:

```bash
bash ./scripts/test-postgres-store.sh
```

What these scripts do:
- start a disposable `postgres:16-alpine` container
- wait for `pg_isready`
- set `BASELINE_TEST_POSTGRES_URL`
- run `go test ./internal/api -run '^TestPostgresStore' -count=1`
- remove the container afterward by default

Useful overrides:
- keep the DB around for inspection:
  - PowerShell: `.\scripts\test-postgres-store.ps1 -KeepContainer`
  - Bash: `KEEP_CONTAINER=1 bash ./scripts/test-postgres-store.sh`
- choose a different host port:
  - PowerShell: `.\scripts\test-postgres-store.ps1 -Port 55433`
  - Bash: `PORT=55433 bash ./scripts/test-postgres-store.sh`
- target a narrower test pattern:
  - PowerShell: `.\scripts\test-postgres-store.ps1 -TestPattern '^TestPostgresStoreProject'`
  - Bash: `TEST_PATTERN='^TestPostgresStoreProject' bash ./scripts/test-postgres-store.sh`

## Staging Cutover Runbook

Use this flow when you want to move an existing SQLite-backed Baseline environment onto Postgres in a staging or pre-production deployment.

### 1) Validate the target Postgres environment

Set the runtime driver and DSN in the target environment:

```env
BASELINE_API_DB_DRIVER=postgres
BASELINE_API_DATABASE_URL=postgres://USER:PASSWORD@HOST:5432/baseline?sslmode=disable
```

Then verify the rest of the production/staging configuration:

```bash
baseline api verify-prod --strict
```

### 2) Migrate the SQLite data into Postgres

Run the migration command against a copy of the SQLite database, not the only live copy:

```powershell
baseline api migrate-postgres --sqlite-path .\baseline_api.db --database-url "postgres://USER:PASSWORD@HOST:5432/baseline?sslmode=disable" --reset-target
```

```bash
baseline api migrate-postgres --sqlite-path ./baseline_api.db --database-url "postgres://USER:PASSWORD@HOST:5432/baseline?sslmode=disable" --reset-target
```

What this does:
- opens the SQLite source database
- opens and bootstraps the Postgres target
- migrates:
  - API keys
  - audit events
  - integration jobs
  - projects and scans
  - users, identities, and auth sessions
  - CLI auth requests, sessions, traces, and trace events
- prints a per-table row-count report at the end

Use `--reset-target` only when you want the target Postgres tables truncated before import.

### 3) Start the API against Postgres

Once migration succeeds, start the API with the Postgres runtime config:

```bash
baseline api serve --addr 0.0.0.0:8080
```

Expected environment:

```env
BASELINE_API_DB_DRIVER=postgres
BASELINE_API_DATABASE_URL=postgres://USER:PASSWORD@HOST:5432/baseline?sslmode=disable
```

### 4) Smoke the cutover

After the API is up on Postgres, verify the main operator flows:

1. `GET /healthz`
2. sign in at `/signin.html`
3. open `/dashboard`
4. confirm projects and scans render
5. confirm existing API keys still load
6. run `baseline dashboard login --api <staging-url>`
7. run a CLI command such as `baseline version` or `baseline scan`
8. confirm the session and trace appear in the dashboard

To automate the public cutover checks:

```powershell
.\scripts\postgres-cutover-smoke.ps1 -BaseURL https://staging.example.com
```

```bash
bash ./scripts/postgres-cutover-smoke.sh https://staging.example.com
```

To include authenticated dashboard/API checks too, pass an admin API key and optionally the migrated project or scan IDs you expect to see:

```powershell
.\scripts\postgres-cutover-smoke.ps1 -BaseURL https://staging.example.com -AdminKey "<admin-key>" -ProjectID proj_123 -ScanID scan_456
```

```bash
bash ./scripts/postgres-cutover-smoke.sh https://staging.example.com "<admin-key>" proj_123 scan_456
```

The cutover smoke scripts verify:
- `/healthz`
- `/signin.html`
- `/dashboard`
- and, when an admin key is provided:
  - `/v1/auth/me`
  - `/v1/dashboard`
  - `/v1/dashboard/capabilities`
  - `/v1/projects`
  - `/v1/scans`

### 5) Rollback plan

If staging validation fails:

1. stop the Postgres-backed API
2. switch the environment back to:
   - `BASELINE_API_DB_DRIVER=sqlite`
   - `BASELINE_API_DB_PATH=<previous path>`
3. restart the API on SQLite
4. keep the migrated Postgres database for inspection instead of mutating it further

## Free-First Deployment

This repo now includes a free-first Render Blueprint at `render.yaml`:

- one Docker-based web service for the Baseline API and dashboard on Render `free`
- external Postgres connection supplied via `BASELINE_API_DATABASE_URL`
- intended pairing:
  - Render Free web service
  - Neon Free Postgres
  - Supabase Free auth
  - Vercel Hobby frontend

What the Blueprint configures for you:
- Postgres as the primary runtime store
- `/healthz` as the zero-downtime health check path
- proxy-aware HTTPS settings
- dashboard session auth enabled
- generated API key hash secret

What you still need to provide in Render during the initial Blueprint setup:
- `BASELINE_API_DATABASE_URL`
- `BASELINE_API_KEY`
- `BASELINE_API_CORS_ALLOWED_ORIGINS`
- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`
- `SUPABASE_AUTH_REDIRECT_TO`
- `BASELINE_API_SUPABASE_URL`
- `BASELINE_API_SUPABASE_CLIENT_ID`
- `BASELINE_API_SUPABASE_CLIENT_SECRET`
- `BASELINE_API_SUPABASE_CALLBACK_URL`

Recommended first deployment flow:
1. create the Render Blueprint from `render.yaml`
2. create a free Neon Postgres database and copy its connection string
3. paste that Neon connection string into `BASELINE_API_DATABASE_URL` in Render
4. use the generated `.onrender.com` hostname for the CORS and Supabase redirect values
5. deploy once
6. run the cutover smoke against the Render URL
7. connect the CLI with:
   - `baseline dashboard login --api https://<your-service>.onrender.com`

Important note:
- this Blueprint is intentionally free-first
- it does not perform the SQLite to Postgres data migration for you
- run `baseline api migrate-postgres ...` first if you are moving an existing environment
- Render Free web services spin down after idle time and are not meant for production
- use UptimeRobot against `/healthz` if you want to reduce cold starts during early testing
- when the app is making money, the clean upgrade path is:
  - Render Free -> paid Render web service
  - Neon Free -> Neon Launch
  - Vercel Hobby -> Vercel Pro if the app becomes commercial

### Why Neon instead of free Render Postgres

Neon Free is the better fit for an early free launch because:

- no credit card required
- no 30-day forced expiry
- scales to zero when idle

Free Render Postgres is much weaker for this stage because:

- only one free database per workspace
- expires after 30 days
- no backups

## Vercel Static Frontend Deployment

If you want the public frontend on Vercel, use `frontend-nodejs` as a static deployment target.

What this gives you well:
- landing page
- sign-in page
- sign-up page
- CLI guide and other static assets

Repo support now included:
- `frontend-nodejs/vercel.json`
- `frontend-nodejs/public/js/runtime-config.js`
- Vite build-time injection for:
  - `SUPABASE_URL`
  - `SUPABASE_ANON_KEY`
  - `SUPABASE_AUTH_REDIRECT_TO`
  - `BASELINE_API_ORIGIN`

Recommended Vercel project settings:
1. Root Directory: `frontend-nodejs`
2. Build Command: `npm run build:prod`
3. Output Directory: `dist`

Required Vercel environment variables:

```env
SUPABASE_URL=https://<your-supabase-project>.supabase.co
SUPABASE_ANON_KEY=<your-supabase-anon-key>
SUPABASE_AUTH_REDIRECT_TO=https://<your-vercel-app>.vercel.app/signin.html?return_to=%2Fdashboard
BASELINE_API_ORIGIN=https://<your-api-host>
```

Important limitation:
- the public static frontend is straightforward on Vercel
- the dashboard expects same-origin `/v1/*` API behavior for the best auth/session experience

This repo now includes a Vercel proxy path for that:
- `frontend-nodejs/api/proxy/[...path].js`
- `frontend-nodejs/vercel.json` rewrites `/v1/*`, `/healthz`, `/readyz`, `/livez`, and `/metrics`

That means the stronger split is now:
- Vercel for the static frontend and same-origin proxy surface
- Baseline API hosted on Render or another server host behind `BASELINE_API_ORIGIN`

Required additional Vercel environment variable for dashboard proxying:

```env
BASELINE_API_ORIGIN=https://<your-api-host>
```

Recommended callback/redirect values when the dashboard itself is served from Vercel:

```env
SUPABASE_AUTH_REDIRECT_TO=https://<your-vercel-app>.vercel.app/signin.html?return_to=%2Fdashboard
BASELINE_API_SUPABASE_CALLBACK_URL=https://<your-vercel-app>.vercel.app/v1/auth/oidc/callback
BASELINE_API_CORS_ALLOWED_ORIGINS=https://<your-vercel-app>.vercel.app
```

With this proxy shape, the browser talks to the Vercel origin, and Vercel forwards the `/v1/*` requests to the Baseline API host. That keeps the dashboard session-cookie flow on one browser origin instead of relying on cross-site cookies.

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

Release automation:
- GitHub releases publish the packaged archives plus checksum files
- GitHub Actions `workflow_dispatch` can generate the same signed release bundle without publishing a release

## Install With npm

If you want a shorter developer-facing install path, Baseline can also be distributed through npm as a wrapper around the compiled GitHub release binaries.

Planned install command:

```bash
npm i -g baselineprod-cli
baseline version
```

Package source:

```text
npm/cli
```

Important:
- publish the GitHub release assets first
- then publish the matching npm package version
- npm package version `1.2.3` should map to GitHub release tag `v1.2.3`
- for local npm package development before a release exists, use:
  - `BASELINE_NPM_SKIP_DOWNLOAD=1 npm install`

## Install From Packaged Releases

The recommended production install path is to use a packaged release archive, not an ad hoc local build.

1. Download the archive for your platform from the GitHub release assets.
2. Download `SHA256SUMS.archives`.
3. Verify the archive checksum.
4. Extract the archive and put `baseline` on your `PATH`.

Example archive names:
- `baseline_v1.2.3_windows_amd64.zip`
- `baseline_v1.2.3_linux_amd64.tar.gz`
- `baseline_v1.2.3_darwin_arm64.tar.gz`

### Verify Checksums

Linux/macOS:

```bash
sha256sum -c SHA256SUMS.archives --ignore-missing
```

Windows PowerShell:

```powershell
$hash = (Get-FileHash .\baseline_v1.2.3_windows_amd64.zip -Algorithm SHA256).Hash.ToLowerInvariant()
Select-String -Path .\SHA256SUMS.archives -Pattern $hash
```

### Verify Release Bundles With Scripts

If you downloaded a packaged release bundle or generated one locally, use the verification scripts:

Linux/macOS:

```bash
bash ./scripts/verify-release.sh .artifacts/release/20260318_120000
```

Windows PowerShell:

```powershell
.\scripts\verify-release.ps1 -RunDir .artifacts\release\20260318_120000
```

These scripts:
- verify `SHA256SUMS.binaries`
- verify `SHA256SUMS.archives`
- verify cosign signatures too when `.sig` and `.pem` files are present

### Verify Keyless Signatures Manually

Published release assets are signed with GitHub Actions keyless cosign.

Example manual verification:

```bash
cosign verify-blob \
  --certificate baseline_v1.2.3_linux_amd64.tar.gz.pem \
  --signature baseline_v1.2.3_linux_amd64.tar.gz.sig \
  --certificate-identity-regexp "https://github.com/johndansu/Baseline/.github/workflows/ci.yml@refs/(heads/.+|tags/.+)" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  baseline_v1.2.3_linux_amd64.tar.gz
```

If you are verifying assets from a fork or different workflow path, override the identity pattern accordingly.

### Extract And Install

Linux/macOS:

```bash
tar -xzf baseline_v1.2.3_linux_amd64.tar.gz
chmod +x baseline
sudo mv baseline /usr/local/bin/baseline
baseline version
```

Windows PowerShell:

```powershell
Expand-Archive .\baseline_v1.2.3_windows_amd64.zip -DestinationPath .\baseline-install
$env:Path = "$PWD\baseline-install;$env:Path"
.\baseline-install\baseline.exe version
```

## Maintainer Release Runbook

Use this flow when you want to validate or publish a Baseline CLI release.

### 1) Validate release packaging without publishing

Use the GitHub Actions manual trigger:

1. Open `Actions` -> `CI/CD Pipeline`.
2. Click `Run workflow`.
3. Optionally set `release_version`.
4. Download the `baseline-release-bundle-<run_number>` artifact after the run completes.

This path packages the release bundle, signs the packaged archives and checksum files, and uploads the output as a workflow artifact without creating a GitHub release.

You can verify the downloaded artifact locally with:

```bash
bash ./scripts/verify-release.sh <artifact-run-dir>
```

### 2) Publish an actual release

1. Make sure the branch you want to release from is green.
2. Create and push a version tag:

```bash
git tag v1.2.3
git push origin v1.2.3
```

3. Publish a GitHub release for that tag.

When the release is published, the `CI/CD Pipeline` release job will:
- package the CLI archives with the tagged version
- generate `SHA256SUMS.binaries` and `SHA256SUMS.archives`
- sign the archives and checksum files with keyless cosign
- attach the packaged artifacts, checksums, signatures, certificates, and metadata to the GitHub release

### 3) Verify the release assets

Check that the release includes:
- platform archives under `archives/`
- `SHA256SUMS.binaries`
- `SHA256SUMS.archives`
- `metadata.txt`
- `RELEASE_INFO.txt`
- `.sig` and `.pem` files for the archives and checksum files

### 4) Sanity-check one install path

Before announcing a release, verify at least one clean install path from the packaged archives:
- Windows: download `.zip`, verify checksum, run `baseline.exe version`
- Linux/macOS: download `.tar.gz`, verify checksum, run `baseline version`

Recommended verification helpers:
- Linux/macOS: `bash ./scripts/verify-release.sh <run-dir>`
- Windows PowerShell: `.\scripts\verify-release.ps1 -RunDir <run-dir>`

### 5) Run a clean-install smoke check

Use the install smoke scripts to simulate a fresh extraction and basic binary startup from a packaged archive.

Linux/macOS:

```bash
bash ./scripts/smoke-install-release.sh .artifacts/release/20260318_120000
```

Windows PowerShell:

```powershell
.\scripts\smoke-install-release.ps1 -RunDir .artifacts\release\20260318_120000
```

These smoke checks:
- verify the release bundle first
- extract the platform archive into a temp directory
- run:
  - `baseline version`
  - `baseline --help`
  - `baseline ci setup --help`

That gives maintainers one repeatable “fresh install works” check before announcing a release.

### 6) Publish the npm wrapper

If you want users to install Baseline with a short terminal command instead of manually downloading archives:

1. publish the GitHub Release first
2. update `npm/cli/package.json` to the matching version
3. from `npm/cli`, run:

```bash
npm publish
```

The npm package is a thin wrapper:
- `postinstall` downloads the matching platform archive from GitHub Releases
- the `baseline` command launches the installed compiled binary

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
