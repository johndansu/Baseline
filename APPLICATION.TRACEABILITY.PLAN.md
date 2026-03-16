# Full Application Traceability Plan

## Objective

Build end-to-end application traceability for Baseline so an admin can answer, with evidence:

- what command ran
- who ran it
- which repository and project it touched
- which major helpers executed
- which branches were taken
- which external calls were made
- where a failure happened
- what the final exit path was

This is application-level traceability. It is not kernel tracing.

## Current State

Baseline now has real CLI traceability, not just partial event telemetry.

What is already in place:

- central trace runtime in `internal/cli/trace`
- central traced command runner in `internal/cli/trace_runner.go`
- batch trace storage and retrieval in the API
- admin trace list and trace detail view in the dashboard
- browser coverage for the CLI trace tab

Current trace storage/API surface:

- `POST /v1/cli/events`
- `POST /v1/cli/traces`
- `GET /v1/cli/traces`
- `GET /v1/cli/traces/{id}`

Current dashboard/admin surface:

- CLI Telemetry tab
- quick filters:
  - all runs
  - warnings only
  - errors only
- command, repository, project, status, and search filters
- grouping by repository and project
- trace detail modal
- JSON export
- trend cards:
  - runs today
  - warnings today
  - errors today

## What Is Actually Covered Now

The traced runner now covers the effective top-level CLI command surface:

- `version`
- `check`
- `enforce`
- `scan`
- `init`
- `report`
- `generate`
- `pr`
- `explain`
- `security-advice`
- `dashboard connect`
- `dashboard status`
- `dashboard disconnect`
- `dashboard serve`
- `api help`
- `api keygen`
- `api verify-prod`
- `api serve`

The highest-value helper coverage is now also in place.

### Check

Covered helper spans include:

- `requireGitRepo`
- `os.Getwd`
- `policy.RunAllChecks`

### Scan

Covered helper spans include:

- `parseScanArgs`
- `loadAPIEnvFiles`
- `requireGitRepo`
- `generateAPIKey`
- `resolveDashboardUploadConfigForScan`
- `maybePromptForDashboardUpload`
- `os.Getwd`
- `scan.RunComprehensiveScan`
- `uploadScanResults`
- `resetSavedDashboardConnection`

### Report

Covered helper spans include:

- `requireGitRepo`
- `parseReportFormat`
- `scan.RunComprehensiveScan`
- `report.OutputText`
- `report.OutputJSON`
- `report.OutputSARIF`

### Generate

Covered helper spans include:

- `requireGitRepo`
- `loadAIEnvFiles`
- `os.Getwd`
- `ai.NewDefaultGenerator`
- `ai.CheckAvailability`
- `policy.RunAllChecks`
- `buildGenerationOutcome`

### PR

Covered helper spans include:

- `requireGitRepo`
- `loadAIEnvFiles`
- `git remote get-url origin`
- `ai.NewDefaultGenerator`
- `ai.CheckAvailability`
- `policy.RunAllChecks`
- `createOrCheckoutBranch`
- `buildGenerationOutcome`
- `commitAndPush`
- `gh pr create`

### Explain

Covered helper spans include:

- `policy.RunAllChecks`
- `report.GetRemediationAdvice`

### Security Advice

Covered helper spans include:

- `requireGitRepo`
- `loadAIEnvFiles`
- `parseSecurityAdviceArgs`
- `ai.NewDefaultGenerator`
- `ai.CheckAvailability`
- `os.Getwd`
- `policy.RunAllChecks`
- `buildSecurityAdviceContext`
- `ai.GenerateSecurityAdvice`
- `ensureSecurityAdviceDisclaimer`
- `os.WriteFile`

### Dashboard Connection Lifecycle

Covered helper spans include:

- `requireGitRepo`
- `loadAPIEnvFiles`
- `parseDashboardConnectArgs`
- `validateAPIBaseURL`
- `resolveOrCreateProjectForConnection`
- `loadBaselineLocalConfig`
- `loadBaselineSecrets`
- `saveBaselineLocalConfig`
- `saveBaselineSecrets`

### Dashboard Status / Disconnect

Covered helper spans include:

- `loadBaselineLocalConfig`
- `loadBaselineSecrets`
- `saveBaselineLocalConfig`
- `saveBaselineSecrets`

### API

Covered helper spans include:

- `loadAPIEnvFiles`
- `generateAPIKey`
- `verifyAPIProdConfig`
- `validateAPIListenAddr`
- `api.NewStore`
- `api.NewServer`
- `api.ListenAndServe`

## What Full Traceability Means Here

For this codebase, full traceability means:

1. Every top-level CLI command starts a trace.
2. Every major helper step can emit structured trace events.
3. Important branch decisions are explicit.
4. External operations are wrapped:
   - HTTP
   - file I/O
   - git calls
   - subprocesses
   - AI/provider calls
5. Failures capture:
   - component
   - function
   - branch
   - error class
   - message
6. The full trace is flushed to the API even on failure.
7. Admin can inspect traces in the dashboard by:
   - command
   - project
   - repository
   - user
   - status
   - trace ID

## What Is Still Not Fully Covered

This is the honest gap list now.

- not every internal helper in every nested path is traced
- not every external call is yet modeled as a dedicated external-call span
- trace redaction policy is still implicit rather than explicitly enforced/tested
- panic-path trace flush coverage is still weaker than the returned-error path
- trace completeness is not enforced by a “new commands must use traced runner” guardrail
- dashboard browser tests exist for the trace tab, but not for the full trace detail ecosystem end to end

This is already strong operational coverage, but it is not mathematically exhaustive.

## Non-Goals

- kernel-level syscall tracing
- OS scheduler tracing
- CPU profiler replacement
- packet capture
- turning every tiny helper into noise

This must stay operationally useful, not become unreadable telemetry spam.

## Trace Event Taxonomy

Current and recommended event types include:

- `cli_command_started`
- `cli_command_completed`
- `cli_helper_entered`
- `cli_helper_exited`
- `cli_branch_taken`
- `cli_warning`
- `cli_error`
- `cli_started`
- `cli_completed`
- `cli_health`
- `cli_config_changed`
- `cli_report_generated`
- `cli_service_started`

Still worth adding more consistently where useful:

- `cli_external_call_started`
- `cli_external_call_completed`
- `cli_external_call_failed`
- `cli_file_read`
- `cli_file_write`
- `cli_config_loaded`
- `cli_config_saved`
- `cli_git_operation`
- `cli_ai_provider_call`
- `cli_exit_code_set`

## Reliability Requirements

The trace system should reliably survive:

- command success
- validation failure
- upload failure
- revoked API key
- panic recovery path
- interrupted background upload

Current state:

- returned-error paths are well covered
- explicit failure branches are well covered
- panic-path guarantees still need stronger proof

## Security Requirements

Never store:

- raw API keys
- bearer tokens
- Supabase session tokens
- full request bodies with secrets
- plaintext credentials

All trace attributes should remain subject to redaction and field discipline.

This is still an area that deserves explicit tests.

## Testing Requirements

What already exists:

### CLI / Go Tests

- trace creation on command start
- helper-level trace assertions on key command paths
- command completion assertions on success and failure paths
- focused trace coverage for:
  - `scan`
  - `report`
  - `generate`
  - `pr`
  - `explain`
  - `security-advice`
  - `dashboard connect`
  - `dashboard disconnect`
  - `api keygen`

### Browser Tests

Playwright coverage exists for the admin CLI trace tab:

- filters, drill-down, and reset
- filter persistence when leaving and returning to the tab

Still missing:

1. panic-flush tests
2. explicit redaction tests
3. broader API trace endpoint auth/error tests
4. more browser coverage around trace detail interactions

## Storage Model

The system is now on the dedicated-trace-table path, which was the right call.

That is better than overloading audit events because:

- trace trees are queryable
- list/detail views are cleaner
- retention is more manageable
- the admin UI has a proper trace model to build on

## Dashboard Requirements

Already landed:

1. trace list
2. trace detail modal
3. error-only and warning-only quick filtering
4. repository/project grouping
5. trend cards

Still worth improving:

- retention/volume stats
- failed-only summary by command over time
- richer trace detail grouping by span tree instead of only flat timeline order

## Rollout Status

### Phase 1: Central Trace Runtime

Status: complete

- `internal/cli/trace`
- `internal/cli/trace_runner.go`

### Phase 2: Core User Commands

Status: complete

- `check`
- `scan`
- `report`
- `generate`
- `pr`
- `explain`
- `security-advice`

### Phase 3: Dashboard and Admin/Service Commands

Status: complete

- `dashboard connect`
- `dashboard status`
- `dashboard disconnect`
- `dashboard serve`
- `api` subcommands
- `version`
- `init`
- `enforce`

### Phase 4: Trace Storage and Admin UI

Status: complete

- trace ingest/list/detail API
- admin CLI telemetry tab
- browser coverage for the trace tab

### Phase 5: Hardening

Status: in progress

Remaining hardening work:

- redaction tests
- panic-path guarantees
- completeness guardrails for future commands
- optional richer external-call event modeling

## Blunt Assessment

Baseline is no longer in the “partial telemetry only” stage.

The command surface is now broadly traced, the traces are stored, the admin can inspect them, and the core admin trace UI has browser coverage. That is a real system, not a sketch.

What is still true:

- this is not exhaustive branch-by-branch tracing of every internal helper
- the remaining work is now hardening and completeness, not basic capability

That is a good place to be.

## Recommended Next Action

The correct next implementation slice is no longer “build tracing.”

It is one of these:

1. add explicit redaction and panic-flush tests
2. add a guardrail so new commands must use the traced runner
3. improve trace detail rendering from a flat timeline to a clearer grouped span tree

Best next step:

- add explicit redaction and panic-flush tests
