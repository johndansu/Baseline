# Changelog

This changelog tracks user-visible Baseline releases and the most important fixes between versions.

## Unreleased

## v1.2.2

### Added
- Added explicit CLI update guidance to the landing page, CLI guide, README, and command reference.
- Added `CHANGELOG.md` as the release-notes source of truth in the repository.

## v1.2.1

### Fixed
- Quieted trace-upload warnings for normal user-facing commands such as `baseline version`, `baseline scan`, `baseline init`, `baseline report`, `baseline generate`, `baseline pr`, `baseline explain`, `baseline security-advice`, and dashboard auth/connect commands.

## v1.2.0

### Changed
- Rolled up the recent CLI and frontend UX improvements into a clean minor release line.

### Fixed
- Restored contrast for project action buttons in the dashboard so admin actions such as `Assign owner` remain visible.
- Clarified the projects page so it matches the real project-creation flow instead of implying a manual add-project workflow.

## v1.1.9

### Fixed
- Streamlined the browser approval bridge used during CLI dashboard approval flows.

## v1.1.8

### Fixed
- Routed CLI approval through the existing dashboard modal instead of a separate approval UI.

## v1.1.7

### Fixed
- Moved CLI approval to a dedicated browser approval page flow.
- Stopped hand-building approval URLs when the API already provides a complete verification URL.
- Refreshed stored dashboard sessions before telemetry upload so trace/event uploads keep working after token refresh.
- Updated browser-login tests to match the current session-start contract.

## v1.1.6

### Fixed
- Defaulted dashboard connect/login flows to the hosted Baseline path instead of falling back to local manual entry.
- Removed the manual dashboard API URL and API key fallback from the normal hosted scan/connect flow.
- Made dashboard connect prefer the stored session API URL when one already exists.

## v1.1.5

### Fixed
- Improved hosted dashboard connect behavior for fresh repositories so session-aware CLI flows work more consistently.

## v1.1.4

### Fixed
- Reused dashboard sessions for project connect where possible.
- Improved dashboard loading behavior during API wake-up so the UI stays in a loading/reconnecting state instead of dropping into a template-looking shell.

## v1.1.3

### Fixed
- Quieted the telemetry warning for ordinary users who have not configured dashboard telemetry.
- Updated public docs and landing copy to reflect npm installation.

## v1.1.2

### Added
- Published the npm wrapper under `baselineprod-cli`.

### Fixed
- Matched the npm release line with the packaged GitHub release assets.

## v1.1.1

### Fixed
- Fixed Bash release packaging to use absolute archive paths so Windows zip creation succeeds reliably.
