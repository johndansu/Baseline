# Baseline Command Reference

## Build and Test
```bash
go build -o baseline ./cmd/baseline
go test ./...
```

## Core CLI
```bash
baseline version
baseline check
baseline enforce
baseline scan
baseline report --json
baseline report --sarif
baseline explain A1
```

## Project Dashboard Upload Flow
```bash
# browser-based CLI session login
baseline dashboard login --api https://baseline-api-95nb.onrender.com

# inspect or clear the current CLI session
baseline dashboard whoami
baseline dashboard logout

# first-time interactive project connection
baseline scan

# explicit project connection management
baseline dashboard connect
baseline dashboard status
baseline dashboard disconnect
```

Notes:
- on first interactive `baseline scan`, Baseline can ask whether the current repository should upload to your dashboard
- the saved project connection is stored in `.baseline/config.yaml`
- the local API key is stored in `.baseline/secrets.json` and is gitignored
- if the saved connection breaks, rerun `baseline dashboard connect`

## AI Commands
```bash
baseline generate
baseline pr
baseline security-advice --out SECURITY.AI.SUGGESTIONS.md
```

## CI Scaffolding
```bash
baseline ci setup --help
baseline ci setup --provider github --mode enforce
```

## API and Auth (Current)
```bash
baseline api keygen
baseline api verify-prod
baseline api verify-prod --strict
baseline api migrate-postgres --sqlite-path ./baseline_api.db --database-url "postgres://USER:PASSWORD@HOST:5432/baseline?sslmode=disable" --reset-target
baseline api serve --addr :8080
# local dashboard proxy service (selected read-only API proxy paths)
baseline dashboard serve --addr 127.0.0.1:8091 --api http://127.0.0.1:8080
```

## Dashboard Upload Examples
```bash
# use saved project-local dashboard connection
baseline scan

# explicit one-off upload override
baseline scan --api http://127.0.0.1:8080 --project-id baseline_repo --api-key <user_api_key>

# inspect or repair the current project connection
baseline dashboard status
baseline dashboard connect --api http://127.0.0.1:8080
baseline dashboard disconnect
```

## Auth Pages (API-hosted)
```text
http://127.0.0.1:8080/
http://127.0.0.1:8080/signin.html
http://127.0.0.1:8080/signup.html
```

## API Key Rotation (Managed Keys)
```powershell
# create a new operator key
.\scripts\api-key-rotate.ps1 `
  -ApiBaseUrl http://127.0.0.1:8080 `
  -AdminApiKey "<current_admin_key>" `
  -Role operator `
  -Name "ops-rotation-01"

# create new key and revoke previous key id
.\scripts\api-key-rotate.ps1 `
  -ApiBaseUrl http://127.0.0.1:8080 `
  -AdminApiKey "<current_admin_key>" `
  -Role operator `
  -Name "ops-rotation-02" `
  -RevokeKeyId "<old_key_id>"
```

## Git and Release
```bash
git status
git add -A
git commit -m "your message"
git push origin main

git tag v1.0.1
git push origin v1.0.1
```

## Branch Protection (GitHub)
Required checks for `main`:
- `Test`
- `Security Scan`
- `Release Gates`
- `API Smoke`

GitHub CLI example:
```bash
gh api \
  -X PUT \
  repos/<owner>/<repo>/branches/main/protection \
  -H "Accept: application/vnd.github+json" \
  -F required_status_checks.strict=true \
  -F required_status_checks.contexts[]="Test" \
  -F required_status_checks.contexts[]="Security Scan" \
  -F required_status_checks.contexts[]="Release Gates" \
  -F required_status_checks.contexts[]="API Smoke" \
  -F enforce_admins=true \
  -F required_pull_request_reviews.required_approving_review_count=1 \
  -F required_pull_request_reviews.dismiss_stale_reviews=true \
  -F restrictions=
```

## Final Release Gate
```bash
bash ./scripts/release-gate.sh
```

```powershell
.\scripts\release-gate.ps1
```

## API Smoke Gate (Production-like)
```bash
bash ./scripts/api-smoke.sh
```

```powershell
.\scripts\api-smoke.ps1
```

## Operator Runbook (API Ops)
```bash
# 1) start service
baseline api serve --addr :8080

# 2) basic health/readiness
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/readyz

# 3) operational metrics
curl http://127.0.0.1:8080/metrics

# 4) auth-protected API probe
curl -H "Authorization: Bearer <admin_key>" \
  http://127.0.0.1:8080/v1/dashboard

# 4b) capability + activity probes
curl -H "Authorization: Bearer <admin_key>" \
  http://127.0.0.1:8080/v1/dashboard/capabilities
curl -H "Authorization: Bearer <admin_key>" \
  "http://127.0.0.1:8080/v1/dashboard/activity?limit=10"

# optional: inspect current human session identity
curl http://127.0.0.1:8080/v1/auth/me

# optional: verify rollout stage before mutation-heavy tests
# (set via BASELINE_API_DASHBOARD_ROLLOUT_STAGE=read_only|mutations|integrations|full)

# 5) audit stream probe
curl -H "Authorization: Bearer <admin_key>" \
  "http://127.0.0.1:8080/v1/audit/events?limit=20"
```

## Incident Triage Quick Checks
```bash
# readiness dependency detail
curl http://127.0.0.1:8080/readyz

# inspect recent failing scan reports
curl -H "Authorization: Bearer <admin_key>" \
  "http://127.0.0.1:8080/v1/scans?project_id=<project_id>"

# fetch SARIF for one scan
curl -H "Authorization: Bearer <admin_key>" \
  "http://127.0.0.1:8080/v1/scans/<scan_id>/report?format=sarif"
```
