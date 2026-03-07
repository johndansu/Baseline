# Security Checklist Status (Auth-First Baseline)

Date: 2026-03-05  
Scope: current auth-first backend path (`internal/api` + API-hosted auth/session flow), with notes where template Node/dashboard code introduces extra risk.

Status legend:
- `PASS`: implemented and validated in code/tests
- `PARTIAL`: control exists but has gaps or assumptions
- `FAIL`: missing control or high-risk behavior present
- `N/A`: not applicable to current scope

## Summary

- Total items: `21`
- `PASS`: `19`
- `PARTIAL`: `0`
- `FAIL`: `0`
- `N/A`: `2`

## 01 â€” Secrets & Config

| # | Checklist Item | Status | Evidence | Action |
|---|---|---|---|---|
| 01.1 | Hardcoded secrets, tokens, or API keys in codebase | PASS | `frontend-nodejs/public/js/supabase-config.js` uses placeholder anon key; API keys loaded from env in `internal/api/config.go`; CI dashboard secret gate runs `scripts/secret-scan-dashboard.sh` with allowlist controls in `security/secret-scan-allowlist.regex` | Keep allowlist minimal and require rationale updates in `security/SECRET.SCAN.md` for any new entry. |
| 01.2 | Secrets leaking through logs, error messages, or API responses | PASS | Go API sanitizes external OIDC responses (`internal/api/handlers_auth_oidc.go`, `internal/api/oidc_auth_test.go`); template auth route responses return generic auth/reset failures (`frontend-nodejs/src/routes/auth.js`) and template error middleware returns stable generic client errors (`frontend-nodejs/src/middleware/logging.js`); structured server log redaction now masks auth headers/cookies/tokens/secrets (`internal/log/logger.go`, `internal/log/logger_test.go`) | Keep redaction tests in CI and extend redaction coverage as new sensitive fields are introduced. |
| 01.3 | Environment files committed to git | PASS | tracked env files are examples: `.env.example`, `frontend-nodejs/.env.example` | Keep only templates in git. |
| 01.4 | API keys exposed client-side that should be server-only | PASS | API keys are server-side in Go API; no server API key material shipped in client assets | Keep API-key operations backend-only. |
| 01.5 | CORS too permissive | PASS | production startup now blocks wildcard CORS and blocks non-HTTPS CORS origins when `BASELINE_API_REQUIRE_HTTPS=true` (`internal/api/startup_validation.go`, `internal/api/startup_validation_test.go`) | Keep this as a startup gate and add integration checks in release smoke tests. |
| 01.6 | Dependencies with known vulnerabilities | PASS | CI Security Scan now enforces `govulncheck` and `npm audit --omit=dev --audit-level=high` in `.github/workflows/ci.yml` | Keep versions and audit level reviewed quarterly. |
| 01.7 | Default credentials or example configs still present | PASS | production startup now rejects placeholder-like API keys, enrollment tokens, OIDC values, and API key hash secret (`internal/api/startup_validation.go`, `internal/api/startup_validation_test.go`) | Keep examples in repo but ensure startup validation remains enabled for production profiles. |
| 01.8 | Debug mode or dev tools enabled in production | PASS | template Node middleware now uses concise production logging and reserves verbose request/response diagnostics + stack traces for non-production only (`frontend-nodejs/src/middleware/logging.js`), with production-path regression coverage (`frontend-nodejs/src/middleware/logging.test.js`) | Keep this policy explicit and require tests for any future logging changes. |

## 02 â€” Access & API

| # | Checklist Item | Status | Evidence | Action |
|---|---|---|---|---|
| 02.1 | Pages or routes accessible without proper auth | PASS | protected API routes call auth (`internal/api/handlers_*`), unauthorized returns `401` | Keep coverage with authz tests per endpoint. |
| 02.2 | Users accessing other users data by changing ID in URL (IDOR) | PASS | ownership checks now apply to both session and non-admin API-key principals for projects/scans/report access (internal/api/authz_scope.go, internal/api/handlers_projects_scans.go, internal/api/server_test.go) | Keep an explicit org/tenant model for future multi-organization deployments. |
| 02.3 | Tokens stored insecurely on the client | PASS | auth-first Go path uses HttpOnly session cookie (`internal/api/handlers_auth_oidc.go`) | Keep session-cookie-first model; avoid localStorage tokens in production path. |
| 02.4 | Login or reset flows reveal whether an account exists | PASS | Go OIDC callback returns generic provider-failure messaging (`internal/api/handlers_auth_oidc.go`); template Node auth routes now use generic sign-in and password-reset responses (`frontend-nodejs/src/routes/auth.js`) with regression coverage in `frontend-nodejs/src/routes/auth.test.js` | Keep response-shape regression tests for sign-in/reset paths. |
| 02.5 | Endpoints missing rate limiting | PASS | rate limiting implemented for general/auth/unauth scopes (`internal/api/rate_limit.go`) | Keep limits tuned and tested. |
| 02.6 | Error responses exposing internal details | PASS | Go API responses are standardized/sanitized; template Node error middleware now returns stable generic error codes/messages and does not echo raw `err.message` to clients (`frontend-nodejs/src/middleware/logging.js`) with regression coverage in `frontend-nodejs/src/middleware/logging.test.js` | Keep explicit tests to prevent accidental reintroduction of raw error propagation. |
| 02.7 | Endpoints returning more data than needed | PASS | API responses are constrained by typed models and do not expose secret material in current Go path | Keep field-minimization review as new endpoints are added. |
| 02.8 | Sensitive actions (delete/change email/etc.) with no confirmation step | PASS | API key revoke enforces confirmation+reason headers and now enforces strict re-auth by default in production startup mode via `POST /v1/auth/reauth` + `X-Baseline-Reauth` (`internal/api/server.go`, `internal/api/sensitive_action.go`, `internal/api/server_test.go`) | Extend this same control to future destructive endpoints. |
| 02.9 | Admin routes protected only by hiding URL | PASS | admin actions enforce role checks server-side (`RoleAdmin` checks in API handlers) | Keep role checks centralized and test-deny paths. |

## 03 â€” User Input

| # | Checklist Item | Status | Evidence | Action |
|---|---|---|---|---|
| 03.1 | Unsanitized input reaching database queries | PASS | Go API validates inputs and store uses parameterized operations (`internal/api/handlers_*`, `internal/api/store.go`) | Keep validation + prepared SQL discipline. |
| 03.2 | User-submitted text that can run code in other usersâ€™ browsers (XSS) | PASS | current auth-first Go-served UI path does not render unescaped user HTML in runtime backend flow | Maintain output encoding policy if/when dashboard reintroduced. |
| 03.3 | File uploads accepted without type/size checks | N/A | no file upload feature in current scope | Reassess when upload endpoints are added. |
| 03.4 | Payment/billing logic bypassable client-side | N/A | no payment/billing feature in current scope | Reassess if billing is introduced. |

## High-Priority Remediation Plan

1. Add dependency security gates in CI (`govulncheck`, `npm audit` for any shipped Node components).  
2. Extend step-up confirmation/re-auth to all future sensitive/destructive actions (user/email changes, account recovery, privilege changes).  
3. Add release-smoke assertions to verify production startup guards reject weak CORS/placeholder configs.  
4. Define tenant/ownership model for project/scan resources before multi-user deployment.  
5. Add periodic security regression runs that execute Go + Node security-focused test subsets in CI.

## Notes on Template Node/Dashboard Code

The status above is for the auth-first Go backend path.  
If `frontend-nodejs` template code is promoted to production without hardening, risk increases (notably token storage and error-message leakage). Re-audit that path separately before release.
