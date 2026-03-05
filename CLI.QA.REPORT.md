# CLI QA Report

Date: 2026-03-03  
Branch: `chore/auth-first-reset`

## Scope

QA executed for:
- top-level commands: `version`, `check`, `enforce`, `scan`, `init`, `report`, `generate`, `pr`, `explain`, `api`, `dashboard`, `security-advice`
- key subcommands/flags: usage/help, invalid flags, and core operational paths

## Pass/Fail Matrix

| Command | Scenario | Result | Notes |
|---|---|---|---|
| `baseline --help` | usage output | PASS | exit `0` |
| `baseline version` | version output | PASS | exit `0` |
| `baseline <unknown>` | invalid command handling | PASS | exit `50` with usage |
| `baseline check` | policy run | PASS | exit `0` in current repo |
| `baseline enforce` | policy enforcement | PASS | exit `0` in current repo |
| `baseline scan` | comprehensive scan | PASS | exit `0` in current repo |
| `baseline report --text` | text report | PASS | exit `0` |
| `baseline report --json` | JSON report | PASS | exit `0` |
| `baseline report --sarif` | SARIF report | PASS | exit `0` |
| `baseline report --bad` | invalid flag | PASS | exit `50` |
| `baseline explain` | missing arg | PASS | exit `50` |
| `baseline explain A1` | policy explain | PASS | exit `0` |
| `baseline init` | init in isolated git repo | PASS | exit `0`; `.baseline/config.yaml` created |
| `baseline api` | missing subcommand | PASS | exit `50` with usage |
| `baseline api keygen` | key generation | PASS | exit `0` |
| `baseline api verify-prod` | config preflight | PASS | expected blocking findings; exit `20` |
| `baseline api verify-prod --strict` | strict preflight | PASS | expected blocking findings; exit `20` |
| `baseline api nope` | invalid subcommand | PASS | exit `50` |
| `baseline api serve` | startup path | PASS | long-running service; startup validated |
| `baseline dashboard --help` | usage output | PASS | exit `0` |
| `baseline dashboard --bad` | invalid flag | PASS | exit `50` |
| `baseline dashboard --api ftp://...` | invalid URL scheme | PASS | exit `50` |
| `baseline dashboard` | startup path | PASS | long-running service; startup validated |
| `baseline generate` | AI scaffold flow | PASS | exit `0` in compliant repo (no work needed) |
| `baseline pr` | AI PR flow | PASS | exit `0` in compliant repo (no PR needed) |
| `baseline security-advice --bad` | invalid flag | PASS | exit `50` |
| `baseline security-advice --out ...` | advisory generation | PASS | exit `0`; file generated with mandatory disclaimer |

## Fixes Applied During QA

1. API address validation hardened:
- Added early validation for `baseline api serve --addr` values.
- Invalid forms (e.g. `bad_addr`, `:`, `:bad`) now fail immediately with clear error, instead of failing later at socket bind.
- Files:
  - `internal/cli/commands.go`
  - `internal/cli/commands_test.go`

## Observations Requiring Product Decision (Not Code Defect)

1. No-arg behavior can auto-start API:
- `baseline` with no args may auto-start API when API keys are configured in env/env files.
- This is by design (`ShouldAutoStartAPI`) but can surprise users expecting usage output.
- Recommendation:
  - keep current behavior but document it prominently in README/command reference, or
  - require explicit `baseline api serve` and remove implicit auto-start behavior.

## Validation Commands

```bash
go build -o baseline-qa.exe ./cmd/baseline
go test ./...
go run ./cmd/baseline --help
```

## Conclusion

CLI command surface is functioning as expected for tested paths.  
One robustness improvement was applied (API address validation).  
No blocking CLI defects remain from this QA pass.
