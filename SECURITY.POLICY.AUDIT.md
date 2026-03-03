# Security Policy Audit (Enterprise-Grade Review)

Date: 2026-03-03  
Scope:
- `internal/policy/checks.go` policy implementation
- CLI command text formatting in `cmd/baseline/main.go`, `internal/cli/commands.go`, `command.md`
- AI advisory feature for additional security recommendations not covered by built-in policies

## Executive Summary

- Baseline has strong foundational controls for a policy gate.
- Current policy set is solid for small/medium teams, but not yet fully enterprise-grade without additional controls in identity, supply chain, cloud posture, provenance, and runtime defense.
- A new AI advisory command is added to generate supplemental security controls:
  - `baseline security-advice --out SECURITY.AI.SUGGESTIONS.md`
- The command always includes this disclaimer text:
  - `AI-generated suggestions may be incorrect. Validate recommendations before implementation.`

## Policy-by-Policy Enterprise Assessment

Legend:
- `Grade A`: Enterprise-ready baseline
- `Grade B`: Good baseline, enterprise gaps remain
- `Grade C`: Useful signal, requires significant expansion for enterprise posture

| Policy | Current Intent | Grade | Enterprise Gaps | Required Upgrade Path |
|---|---|---|---|---|
| A1 | Primary branch protected, PR-only/restricted pushes | B | Does not validate required CODEOWNERS approvals, merge queue, signed commits, review freshness | Add branch protection depth checks via GitHub API: required reviewers count, code owner reviews, dismissal rules, signed commit enforcement |
| B1 | CI runs on PR + tests present | B | No assertion on artifact signing/SLSA/provenance/security jobs success | Add checks for required security jobs (SAST, dependency scan, secrets scan, provenance) and required status contexts |
| C1 | Tests exist | C | Presence check only; no coverage quality, critical-path tests, flaky-test controls | Add minimum coverage threshold and required integration/e2e test gates for protected branches |
| D1 | Plaintext secret detection patterns | B | Regex-based and limited token set; false positives/negatives possible; no entropy or historical scan | Add entropy + high-confidence token detectors, provider-specific signatures, and optional historical git scan mode |
| E1 | Dependency management files exist | C | No vulnerability, freshness, or lockfile integrity enforcement | Add CVE threshold gates, lockfile required checks, stale dependency policy, and allowlist exceptions workflow |
| F1 | README + license required | C | Not security-focused; no security docs requirement | Require `SECURITY.md`, threat model pointer, and incident response contact metadata |
| G1 | Blocks risky code patterns (unsafe/exec/eval/SQL concatenation) | B | Pattern checks are narrow; no language-specific taint analysis | Add semgrep/codeql integration checks and rule pack versioning |
| H1 | Deployment config exists + Docker non-root + latest tag warning | B | No image hardening checks (capabilities, distroless, readonly fs, seccomp) | Add container baseline rules: read-only rootfs, dropped capabilities, explicit user/group, pinned digest support |
| I1 | IaC artifacts exist | C | Presence check only; no misconfiguration scanning | Add IaC policy scans (terraform/k8s/cloudformation) with blocking severities |
| J1 | Env template exists | C | No required variable schema, no secret source validation | Add env schema validation and secret-source policy (vault/secret manager references only) |
| K1 | Backup/recovery docs/scripts exist | C | No RPO/RTO, restore test proof, encryption requirements | Require restore drill evidence and recovery objectives in policy artifacts |
| L1 | Logging/monitoring docs/config exist | C | No production telemetry SLO or security event requirements | Enforce minimum observability controls (audit logs, auth failures, alert rules, retention) |
| R1 | Rollback documentation exists | B | No automated rollback readiness or validation | Add release rollback test/checklist artifacts and runbook validation |

## Additional Enterprise Controls Missing from Current Policy Set

These are the highest-priority controls to become enterprise-grade:

1. Identity and access:
- mandatory SSO/SAML enforcement for org
- least-privilege role controls for CI tokens and bots
- short-lived credentials (OIDC federation) instead of static secrets

2. Supply chain and provenance:
- SBOM generation and validation in CI
- signed artifacts and provenance attestations
- dependency trust policy (allowed registries, checksum verification)

3. Cloud/infrastructure posture:
- baseline IaC policy checks for public exposure, encryption, IAM over-permission
- runtime hardening checks for container/workload security context

4. Security operations readiness:
- incident response runbook and on-call escalation checks
- evidence of backup restore drills
- production alert coverage and MTTD/MTTR metrics

5. Data protection:
- encryption-at-rest/in-transit policy assertions
- data classification and retention checks for logs/artifacts

## AI Advisory Feature Added

New CLI command:

```bash
baseline security-advice --out SECURITY.AI.SUGGESTIONS.md
```

Behavior:
- Uses configured AI provider (Ollama/OpenRouter) through existing AI stack.
- Builds recommendations for controls not already covered by A1/B1/.../R1.
- Writes output to file (default: `SECURITY.AI.SUGGESTIONS.md`).
- Always includes mandatory disclaimer:
  - `AI-generated suggestions may be incorrect. Validate recommendations before implementation.`

## CLI Command Text Formatting Audit

Status: Completed.

Actions performed:
- Added `security-advice` to CLI help output.
- Replaced non-ASCII/garbled status markers in CLI output with ASCII:
  - changed checkmark output to `[OK] ...`
- Verified command help text renders cleanly.
- Verified no non-ASCII text remains in:
  - `cmd/baseline/main.go`
  - `internal/cli/commands.go`
  - `command.md`

Validation executed:
- `go test ./internal/ai ./internal/cli ./cmd/baseline`
- `go run ./cmd/baseline --help`
- ASCII scan for CLI command text files

## Decision

Current policies are strong as a deterministic baseline, but not yet complete for full enterprise security assurance.  
Recommended path:
1. Keep current policies as mandatory baseline gates.
2. Add enterprise extensions in a new advanced policy tier.
3. Use `baseline security-advice` as supplemental guidance only, never as enforcement truth.
