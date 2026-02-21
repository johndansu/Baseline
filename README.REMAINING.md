# Remaining Work Backlog

_Last updated: 2026-02-18_

Detailed backend execution plan: `BACKEND.IMPLEMENTATION.PLAN.md`

## Current State Snapshot
- `go test ./...` passes.
- `go build ./cmd/baseline` passes.
- Latest GitHub Actions run on `main` was green at last verification (`CI/CD Pipeline` run `#44`, created 2026-02-18T15:59:37Z).
- Local policy check passes (`A1` closed via branch protection validation).

## What Next (Execution Order)
1. Close `A1` immediately.
- Apply real branch protection on `main` (PR-only merges, required checks, restrict direct push) and re-run `baseline check`.

2. Clean repository artifacts.
- Remove tracked `coverage` and `baseline.exe`, keep both ignored, and verify with `git ls-files`.

3. Security hygiene before any release.
- Rotate previously exposed AI/API credentials and verify no secret values exist in repo history or runtime logs.

4. Lock compliance fidelity.
- Implement the P1 integrity items (`A1` real validation + `B1` semantic CI parsing + manifest/runtime severity alignment) and ship tests.

5. Release-gate run.
- Run full suite: `go test ./...`, `baseline check`, `baseline report --json`, `baseline report --sarif`, CI pipeline on `main`.

## Rollback Procedure (Operator)
1. Identify target rollback commit/tag.
- Use `git log --oneline --decorate -n 20` and select last known-good release.

2. Revert deployment manifest or release reference.
- Point runtime/deployment to prior image/binary tag.
- Avoid force-push on `main`; use revert commits for traceability.

3. Rotate affected managed API keys if rollback was incident-driven.
- Revoke compromised key IDs with `DELETE /v1/api-keys/{id}`.
- Issue replacement keys and update runtime secrets.

4. Validate post-rollback health.
- `curl http://127.0.0.1:8080/healthz`
- `curl http://127.0.0.1:8080/readyz`
- `curl http://127.0.0.1:8080/metrics`

5. Verify policy and audit posture.
- Run `baseline check`.
- Query `GET /v1/audit/events?limit=50` and confirm rollback/change events are visible.

6. Document rollback evidence.
- Incident ID, operator, timestamps, impacted services, restored commit/tag, and validation outputs.

## Production Release Checklist
1. Local hardening gate passes.
- `go test ./...`
- `baseline check`
- `baseline report --json`
- `baseline report --sarif`

2. API-specific gates pass.
- API contract checks.
- Backend e2e suite (`auth/projects/scans/policies/rulesets/audit`).
- API high-read performance smoke tests.

3. CI required checks configured on `main`.
- Require these checks in branch protection:
  - `Test`
  - `Security Scan`
  - `Release Gates`
  - `Build`
- Enforce PR-only merges and restrict direct pushes.

4. Security and secrets validated.
- No plaintext secrets committed.
- Runtime credentials rotated/active.

5. Artifact and release integrity confirmed.
- Release binaries built.
- `SHA256SUMS` published.
- Cosign signatures/certificates attached.

## Production Readiness (Current)
- Engineering readiness: `~80%` (build/tests/CI mostly stable).
- Compliance readiness: `~60%` (blocking `A1` still open, rule-fidelity hardening pending).
- Operational readiness: `~70%` (API/dashboard functional, but credential and release-hardening tasks remain).
- Overall production readiness: `~70%` for a controlled beta, `not ready` for strict production launch until P0 is complete.

Go-live minimum gate:
- `baseline check` must exit `0` on `main`.
- No tracked local artifacts (`coverage`, local binaries).
- Credentials rotated and verified clean.
- P1 compliance-fidelity tests merged and green in CI.

## Compliance Rules (Current Baseline Set)
1. `A1` Protected primary branch.
2. `B1` CI pipeline required.
3. `C1` Test suite exists.
4. `D1` No plaintext secrets.
5. `E1` Dependency management exists.
6. `F1` Documentation requirements (`README` and `LICENSE`).
7. `G1` Risky code/security pattern checks.
8. `H1` Deployment configuration exists.
9. `I1` Infrastructure as code exists.
10. `J1` Environment variable template/config exists.
11. `K1` Backup and recovery documentation exists.
12. `L1` Logging and monitoring requirements exist.
13. `R1` Rollback plan exists.

Compliance integrity status:
- Closed: `A1` now verifies real GitHub branch protection via API when available and no longer accepts docs-only proxy evidence.
- Closed: `B1` now parses GitHub Actions workflows semantically and requires tests in pull_request-triggered workflows.
- Closed: `policy-manifest.yaml` severities are aligned to blocking enforcement and covered by regression test.

## Future Compliance Programs (Planned)
1. SOC 2 Type I and Type II.
- Focus: security, availability, confidentiality, change management, access control evidence.
- Evidence outputs: policy run history, control mapping, exceptions/waivers, approver trail, signed release artifacts.

2. ISO/IEC 27001.
- Focus: ISMS control coverage, risk treatment linkage, operational control evidence.
- Evidence outputs: control-to-policy mappings, audit events, incident/rollback evidence, vulnerability management snapshots.

3. ISO/IEC 27017 and 27018.
- Focus: cloud security controls and privacy controls for cloud processing.
- Evidence outputs: cloud configuration checks, tenancy/separation controls, privacy handling evidence.

4. ISO/IEC 27701.
- Focus: privacy information management controls and governance.
- Evidence outputs: data handling control results, data-subject process evidence, retention/deletion audit trail.

5. NIST CSF 2.0 alignment.
- Focus: Identify, Protect, Detect, Respond, Recover coverage over engineering workflows.
- Evidence outputs: framework mapping report from Baseline policies to NIST functions and categories.

6. NIST 800-53 moderate baseline (select profile support).
- Focus: technical and procedural controls needed for regulated environments.
- Evidence outputs: machine-generated control evidence bundles with control IDs and timestamps.

7. CIS Critical Security Controls mapping.
- Focus: practical prioritized safeguards tied to CI/CD and code governance.
- Evidence outputs: control status matrix and drift reports.

8. PCI DSS 4.0 support profile.
- Focus: secure software lifecycle, vulnerability management, access restrictions, logging.
- Evidence outputs: release gate evidence, dependency/security scan attestations, immutable audit logs.

9. HIPAA Security Rule support profile.
- Focus: access controls, integrity, transmission security, audit controls.
- Evidence outputs: access/auth evidence, API audit events, incident and recovery documentation traces.

10. GDPR and CCPA privacy support profile.
- Focus: lawful processing safeguards, minimization, deletion/retention controls, auditability.
- Evidence outputs: privacy control checks, retention enforcement logs, DSAR process evidence exports.

11. Internal control framework program.
- Focus: custom enterprise controls, control owners, review cadence, exceptions.
- Evidence outputs: internal controls catalog, policy-to-control traceability, recurring compliance snapshots.

## Future Rules Roadmap (Proposed)
1. `M1` SAST required in CI.
- Done when: CI config contains a blocking static analysis step for push and PR on protected branches.

2. `N1` Dependency vulnerability gating.
- Done when: known high/critical CVEs fail policy unless explicitly waived.

3. `O1` SBOM generation and artifact retention.
- Done when: each build produces an SBOM artifact and retains it for audit.

4. `P1` Release artifact integrity.
- Done when: release binaries ship with checksums and signatures/attestations.

5. `Q1` Mandatory CODEOWNERS review for protected paths.
- Done when: changes under sensitive directories require designated approvers.

6. `S1` Incident response/runbook readiness.
- Done when: repo contains an incident playbook with owner, severity matrix, and escalation flow.

7. `T1` API runtime hardening baseline.
- Done when: auth, rate limiting, body limits, and security headers are enforced and tested.

8. `U1` Audit trail integrity.
- Done when: audit events are immutable, queryable, and include actor/action/timestamp metadata.

9. `V1` Backup restore drill evidence.
- Done when: restore test evidence is present and no older than defined policy window.

10. `W1` Policy waiver governance.
- Done when: temporary waivers require owner, reason, expiry, and are surfaced in reports.

## Future Rules Delivery Plan
### Phase `v1.1` (2 sprints)
1. Deliver `M1`, `N1`, `P1`.
- Files: `.github/workflows/ci.yml`, `internal/policy/checks.go`, `internal/types/types.go`, `internal/report/report.go`.
- Tests: `internal/policy/checks_test.go`, `internal/cli/commands_test.go`, `internal/report/report_test.go`.

2. Deliver `Q1`.
- Files: `.github/CODEOWNERS`, `internal/policy/checks.go`, `README.md`.
- Tests: `internal/policy/checks_test.go`.

### Phase `v1.2` (2-3 sprints)
1. Deliver `O1`, `T1`, `U1`.
- Files: `.github/workflows/ci.yml`, `internal/api/server.go`, `internal/api/store.go`, `internal/api/types.go`, `internal/policy/checks.go`.
- Tests: `internal/api/server_test.go`, `internal/api/config_test.go`, `internal/policy/security_test.go`.

2. Deliver `W1`.
- Files: `internal/policy/checks.go`, `internal/report/report.go`, `internal/cli/commands.go`, `policy-manifest.yaml`.
- Tests: `internal/policy/regression_test.go`, `internal/report/report_test.go`, `internal/cli/commands_test.go`.

### Phase `v2.0` (platform maturity)
1. Deliver `S1`, `V1`.
- Files: `README.md`, `CHANGELOG.md`, `policy-manifest.yaml`, runbooks in `docs/` (new).
- Tests: policy fixtures in `internal/policy/checks_test.go` + CI docs gate in `.github/workflows/ci.yml`.

2. Stabilize governance and compatibility.
- Files: `internal/types/types.go`, `internal/policy/checks.go`, `internal/api/assets/openapi.yaml`.
- Tests: full suite `go test ./...` plus release smoke checks for CLI + API.

## P0 (Must Fix)
1. Remove accidental tracked artifacts from repository history and default branch.
- Scope: remove tracked `coverage` and tracked local binary `baseline.exe` from Git, keep them ignored.
- Why: repository hygiene, smaller clone size, cleaner diffs, less risk of shipping local artifacts.
- Done when: `git ls-files coverage baseline.exe` returns no results and `.gitignore` keeps them excluded.

2. Resolve `A1` for this repository configuration.
- Scope: enforce GitHub branch protection on `main` (PR required, status checks required, restrict direct pushes).
- Why: Baseline currently blocks on this repo's own branch protection verification.
- Done when: `baseline check` exits `0` in this repository.

3. Rotate exposed AI credentials and verify no secret leakage paths.
- Scope: rotate any OpenRouter/API key that was shared externally; keep runtime keys only in env/secret manager.
- Why: credential safety.
- Done when: rotated key is active, old key revoked, and no secrets are committed or logged.

## P1 (High Priority)
1. Replace A1 proxy/evidence checks with real branch protection validation.
- Scope: check actual host protection state (GitHub API when remote is GitHub), use deterministic fallback only when API is unavailable.
- Why: stronger obligation mapping than doc-file proxies.
- Status: `done` (2026-02-18).

2. Harden CI obligation parsing beyond substring matching.
- Scope: parse CI config semantically (at least GitHub Actions YAML) to validate PR triggers and test execution more reliably.
- Why: reduce false positives/false negatives in `B1`.
- Status: `done` (2026-02-18).

3. Align policy manifest severities with runtime enforcement.
- Scope: eliminate warn/block drift between `policy-manifest.yaml` and policy engine behavior.
- Why: make contract deterministic for users and automation.
- Status: `done` (2026-02-18, guarded by test).

4. Add CLI end-to-end conformance tests for exit code contract.
- Scope: black-box tests for `check`, `scan`, `report` (`--text/--json/--sarif`, invalid flags), and no-arg behavior.
- Why: protect script-safety guarantees across releases.
- Status: `done` (2026-02-18).

5. Add release hardening for distributed binaries.
- Scope: checksums + signature/attestation for release artifacts.
- Why: supply-chain trust for customer installs.
- Status: `done` (2026-02-18, release workflow publishes SHA256SUMS + keyless cosign signatures/certs).

## P2 (Product Maturity)
1. API onboarding UX hardening.
- Scope: improve first-run setup flow for API keys and dashboard auth (clear setup path, deterministic errors, least-friction local start).
- Done when: new user can go from clone to authenticated dashboard/API in one documented flow.

2. Dashboard/API contract parity regression checks.
- Scope: add tests to ensure dashboard calls only implemented/authorized endpoints.
- Done when: dashboard integration tests catch route/auth regressions before release.

3. Documentation policy cleanup.
- Scope: revisit current global ignore rule for `*.md`/`*.txt` to avoid blocking important future docs.
- Done when: doc strategy is explicit and supports changelogs/runbooks/spec updates without git friction.
