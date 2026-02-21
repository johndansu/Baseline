# Baseline

Baseline is a Go CLI and optional API/dashboard layer for enforcing deterministic production-readiness checks before code ships.

This README reflects what is currently implemented in this repository.

## What You Have In This Repo

- A CLI in `cmd/baseline` with policy checks, scan/report output, and init/explain flows.
- Deterministic policy enforcement in `internal/policy`.
- AI-assisted scaffolding commands in `internal/ai` (Ollama or OpenRouter, human review required).
- An HTTP API server with auth/session support in `internal/api`.
- Two dashboard paths:
  - Embedded dashboard at `/dashboard` from `baseline api serve`.
  - Separate dashboard proxy from `baseline dashboard`.
- Static frontend pages in `frontend/` for local browser preview.

## Requirements

- Go `1.24.13+` (or Go `1.25+`) (see `go.mod`)
- Git installed and available in PATH
- Optional:
  - Ollama, or OpenRouter API access (for `baseline generate` and `baseline pr`)
  - GitHub CLI (`gh`) for `baseline pr`

## Build

```bash
go build -o baseline.exe ./cmd/baseline
```

## CLI Commands

- `baseline version` - print version/build information.
- `baseline check` - run all policy checks and exit non-zero on violations.
- `baseline enforce` - enforcement-focused output; blocks on violations.
- `baseline scan` - run comprehensive scan summary (files/security/violations).
- `baseline init` - create `.baseline/config.yaml`.
- `baseline report` - output scan results (`--text`, `--json`, `--sarif`).
- `baseline explain <policy_id>` - explain current status + remediation for one policy.
- `baseline generate` - generate scaffolded fixes for certain violations via configured AI provider.
- `baseline pr` - generate fixes, commit/push branch, and try `gh pr create`.
- `baseline api serve` - run API server.
- `baseline api keygen` - generate a random API key.
- `baseline api verify-prod [--strict]` - validate production API env configuration.
- `baseline dashboard` - run separate local dashboard proxy service.

## Exit Codes

- `0` success
- `20` blocking violations
- `50` system/runtime error

## Policy Checks Enforced

Baseline currently runs these checks (IDs from `internal/types/types.go`):

- `A1` primary branch protection is verified (PR-required and direct push restrictions), using GitHub API when available and config fallback when needed.
- `B1` CI workflows must run on pull requests and execute automated tests in PR-triggered jobs.
- `C1` automated tests exist.
- `D1` no plaintext secrets/token patterns in scannable files.
- `E1` dependency management files exist.
- `F1` README + license requirements are met.
- `G1` risky code patterns are blocked (unsafe pointer, unsafe exec/eval/system, SQL string building).
- `H1` deployment config exists; Dockerfile rules include non-root `USER`.
- `I1` infrastructure-as-code artifacts exist.
- `J1` environment variable template exists (`.env.example`/`.env.template` style).
- `K1` backup/recovery docs or scripts exist.
- `L1` logging/monitoring config or docs exist.
- `R1` rollback documentation exists.

Notes:
- Most violations are `block`.
- Dockerfile use of `:latest` is currently reported as `warn`.

## Command Reference

For a concise day-to-day command list, see `command.md`.

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

- API key auth via `Authorization: Bearer <key>`.
- Optional dashboard cookie sessions via `/v1/auth/session` when `BASELINE_API_DASHBOARD_SESSION_ENABLED=true`.
- Optional self-service API key registration via `/v1/auth/register` when enabled (server issues the key; client submits `enrollment_token`).
- API key lifecycle management endpoints: create/list/revoke via `/v1/api-keys` (admin for create/revoke).
- Optional signed webhook ingestion for GitHub/GitLab under `/v1/integrations/*/webhook`.
- Webhook ingestion now enqueues persistent integration jobs in SQLite and processes them with background retry/backoff worker logic.
- Session-authenticated mutating requests require `X-Baseline-CSRF: 1`.
- API keys and audit events are persisted in SQLite at `BASELINE_API_DB_PATH`.

### Implemented API Routes (Current)

- `GET /`
- `GET /dashboard`
- `GET /assets/baseline-logo.png`
- `GET /assets/dashboard.css`
- `GET /assets/dashboard.js`
- `GET /openapi.yaml`
- `GET /metrics`
- `GET /healthz` and `GET /livez`
- `GET /readyz`
- `POST|GET|DELETE /v1/auth/session`
- `POST /v1/auth/register`
- `GET|POST /v1/api-keys`
- `DELETE /v1/api-keys/{key_id}`
- `POST /v1/integrations/github/webhook`
- `POST /v1/integrations/gitlab/webhook`
- `POST /v1/integrations/github/check-runs`
- `POST /v1/integrations/gitlab/statuses`
- `GET /v1/dashboard`
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

### API Environment Variables

- `BASELINE_API_ENV_FILE`
- `BASELINE_API_ADDR`
- `BASELINE_API_DB_PATH`
- `BASELINE_API_KEY`
- `BASELINE_API_KEYS`
- `BASELINE_API_KEY_HASH_SECRET`
- `BASELINE_API_REQUIRE_HTTPS`
- `BASELINE_API_SELF_SERVICE_ENABLED`
- `BASELINE_API_ENROLLMENT_TOKENS`
- `BASELINE_API_ENROLLMENT_TOKEN_TTL_MINUTES`
- `BASELINE_API_ENROLLMENT_TOKEN_MAX_USES`
- `BASELINE_API_TIMEOUT_MS`
- `BASELINE_API_IDLE_TIMEOUT_MS`
- `BASELINE_API_MAX_BODY_BYTES`
- `BASELINE_API_SHUTDOWN_TIMEOUT_MS`
- `BASELINE_API_CORS_ALLOWED_ORIGINS`
- `BASELINE_API_TRUST_PROXY_HEADERS`
- `BASELINE_API_DASHBOARD_SESSION_ENABLED`
- `BASELINE_API_DASHBOARD_SESSION_ROLE`
- `BASELINE_API_DASHBOARD_SESSION_TTL_MINUTES`
- `BASELINE_API_DASHBOARD_SESSION_COOKIE_SECURE`
- `BASELINE_API_DASHBOARD_AUTH_PROXY_ENABLED`
- `BASELINE_API_DASHBOARD_AUTH_PROXY_USER_HEADER`
- `BASELINE_API_DASHBOARD_AUTH_PROXY_ROLE_HEADER`
- `BASELINE_API_GITHUB_WEBHOOK_SECRET`
- `BASELINE_API_GITLAB_WEBHOOK_TOKEN`
- `BASELINE_API_GITHUB_TOKEN`
- `BASELINE_API_GITHUB_API_URL`
- `BASELINE_API_GITLAB_TOKEN`
- `BASELINE_API_GITLAB_API_URL`
- `BASELINE_API_RATE_LIMIT_ENABLED`
- `BASELINE_API_RATE_LIMIT_REQUESTS`
- `BASELINE_API_RATE_LIMIT_WINDOW_SECONDS`
- `BASELINE_API_AUTH_RATE_LIMIT_REQUESTS`
- `BASELINE_API_AUTH_RATE_LIMIT_WINDOW_SECONDS`
- `BASELINE_API_UNAUTH_RATE_LIMIT_REQUESTS`
- `BASELINE_API_UNAUTH_RATE_LIMIT_WINDOW_SECONDS`
- `BASELINE_API_AI_ENABLED`

Env files are auto-loaded in this order:
`BASELINE_API_ENV_FILE` (if set), `.env.production`, `.env`, `api.env`.

For managed API key rotation, use `scripts/api-key-rotate.ps1`.

### Operator Runbook (Quick Ops)

1. Start API with explicit config:

```bash
baseline api serve --addr :8080
```

2. Verify liveness and readiness:

```bash
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/readyz
```

3. Check operational metrics:

```bash
curl http://127.0.0.1:8080/metrics
```

4. Confirm auth and dashboard payload path:

```bash
curl -H "Authorization: Bearer <admin_key>" http://127.0.0.1:8080/v1/dashboard
```

5. Inspect recent audit trail:

```bash
curl -H "Authorization: Bearer <admin_key>" "http://127.0.0.1:8080/v1/audit/events?limit=20"
```

6. Rotate/revoke managed API keys:

```powershell
.\scripts\api-key-rotate.ps1 `
  -ApiBaseUrl http://127.0.0.1:8080 `
  -AdminApiKey "<admin_key>" `
  -Role operator `
  -Name "ops-rotation-01" `
  -RevokeKeyId "<old_key_id>"
```

7. Production preflight:

```bash
baseline api verify-prod --strict
bash ./scripts/release-gate.sh
```

Windows PowerShell:

```powershell
.\scripts\release-gate.ps1
```

## Dashboard Options

### 1) Embedded Dashboard (API-hosted)

Run:

```bash
baseline api serve --addr :8080
```

Open:

`http://127.0.0.1:8080/dashboard`

Windows shortcut:

```bat
run-dashboard.bat
stop-dashboard.bat
```

### 2) Proxy Dashboard Service

Run API first, then:

```bash
baseline dashboard --addr 127.0.0.1:8091 --api http://127.0.0.1:8080
```

Open:

`http://127.0.0.1:8091/`

This dashboard proxies selected GET endpoints under `/proxy/...`.

## Frontend Static Mode

For static page preview (no API required):

- Open `frontend/index.html`
- Open `frontend/dashboard.html`

Assets used:

- `frontend/styles.css`
- `frontend/app.js`
- `img/baseline logo.png`

## AI Scaffolding

Baseline uses AI for scaffolding only:

- `baseline generate` can create CI/test/README/Dockerfile/env-template scaffolds based on violations.
- `baseline pr` can generate files, commit, push branch, and attempt PR creation.
- AI provider config:
  - `AI_PROVIDER=ollama` with `OLLAMA_URL` and optional `OLLAMA_MODEL`
  - `AI_PROVIDER=openrouter` (or set `OPENROUTER_API_KEY` to auto-select) with `OPENROUTER_API_KEY`, optional `OPENROUTER_MODEL`, optional `OPENROUTER_URL`
  - automatic fallback: when provider is `ollama` and `OPENROUTER_API_KEY` is set, Baseline falls back to OpenRouter if Ollama availability/check or request calls fail
  - optional env file auto-load for these commands: `BASELINE_AI_ENV_FILE`, `.env.production`, `.env`, `ai.env`, `api.env`

AI is not used to decide enforcement outcomes. Review generated content before merge.

## Test

```bash
go test ./...
```

## Release Integrity

Release artifacts are hardened in CI:

- `SHA256SUMS` is generated for release binaries.
- Binaries and checksums are keylessly signed with Sigstore Cosign.
- Signatures (`.sig`) and certificates (`.pem`) are uploaded with release assets.

## Security

See `SECURITY.md` for vulnerability reporting.

## License

MIT License (`LICENSE`).
