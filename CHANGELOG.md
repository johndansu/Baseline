# Changelog

All notable user-facing changes to Baseline are tracked here.

This changelog is intentionally focused on what users, operators, and maintainers will notice:
- CLI behavior changes
- dashboard and auth flow changes
- release/install changes
- documentation and onboarding changes that affect real usage

Internal refactors and low-level test churn are omitted unless they changed shipped behavior.

## Unreleased

## v1.2.2 - 2026-03-30

### Added
- Added a real `CHANGELOG.md` so releases have one source of truth in the repository.
- Added explicit CLI update guidance across the landing page, CLI guide, README, and command reference.

### Changed
- Clarified the recommended update path for fast-moving CLI releases:
  - `npm i -g baselineprod-cli@latest`
- Added a mobile-only dashboard banner that keeps access open but makes it clear that project management, scans, keys, and operator-heavy workflows are best handled on desktop.

### Why this release matters
- Users now have a clear way to tell whether they should update before troubleshooting or trying a newly shipped flow.
- Mobile users now get a clearer expectation about what works well on phones versus what is better on desktop.

## v1.2.1 - 2026-03-30

### Fixed
- Quieted skipped-trace warnings for normal user-facing commands such as:
  - `baseline version`
  - `baseline scan`
  - `baseline init`
  - `baseline report`
  - `baseline generate`
  - `baseline pr`
  - `baseline explain`
  - `baseline security-advice`
  - dashboard auth/connect/status commands

### Changed
- Kept the skipped-trace warning for more operator-oriented or infrastructure-oriented flows where missing telemetry is still useful signal, such as:
  - `check`
  - `enforce`
  - `ci`
  - `api ...`
  - `dashboard serve`

### Why this release matters
- The CLI feels much cleaner in normal usage because routine commands no longer end with admin-ish trace upload noise.

## v1.2.0 - 2026-03-29

### Changed
- Promoted the recent CLI and frontend UX improvements into a clean minor release line.
- Improved the overall product feel of the hosted dashboard and project pages after several fast patch releases.

### Fixed
- Restored contrast for project action buttons in the dashboard so admin actions such as `Assign owner` remain visible.
- Clarified the projects page so it reflects the real project flow instead of implying that users must create projects manually from the dashboard first.

### Why this release matters
- This is the first release in the `1.2.x` line and marks the point where the CLI/dashboard experience became noticeably more polished.

## v1.1.9 - 2026-03-29

### Fixed
- Streamlined the browser approval bridge used during CLI dashboard approval flows.
- Reduced the awkward feeling of a duplicate or overly heavy intermediate approval step before the main dashboard modal.

### Why this release matters
- CLI-to-dashboard login and approval started feeling more like one continuous product flow instead of a stack of separate pages.

## v1.1.8 - 2026-03-29

### Fixed
- Routed CLI approval through the existing dashboard modal instead of a separate custom approval UI.

### Changed
- Moved the approval experience closer to the dashboard patterns users already understood.

### Why this release matters
- This was an important cleanup for trust and consistency in the browser-based CLI login flow.

## v1.1.7 - 2026-03-29

### Fixed
- Moved CLI approval to a dedicated browser approval page flow.
- Stopped hand-building approval URLs when the API already provides a complete verification URL.
- Refreshed stored dashboard sessions before telemetry upload so trace and event uploads continue working after access-token expiry.
- Updated browser-login tests to match the current session-start contract.

### Changed
- Tightened the contract between CLI auth, dashboard approval, and server-provided verification URLs.

### Why this release matters
- This release addressed real auth-flow correctness issues, not just polish.

## v1.1.6 - 2026-03-29

### Fixed
- Defaulted dashboard connect and login flows to the hosted Baseline path instead of falling back to local manual entry.
- Removed the manual dashboard API URL and API key fallback from the normal hosted scan/connect flow.
- Made dashboard connect prefer the stored session API URL when one already exists.

### Changed
- Shifted the CLI from a local-first fallback model toward a hosted-first onboarding model.

### Why this release matters
- This release made first-run hosted usage much less confusing, especially for users who never intended to self-host.

## v1.1.5 - 2026-03-28

### Fixed
- Improved hosted dashboard connect behavior for fresh repositories so session-aware CLI flows work more consistently.

### Why this release matters
- This was an important step in making `baseline scan` and dashboard connection flows feel reliable in new repos.

## v1.1.4 - 2026-03-28

### Fixed
- Reused dashboard sessions for project connect where possible.
- Improved dashboard loading behavior during API wake-up so the UI stayed in a loading/reconnecting state instead of dropping into a template-looking shell.

### Changed
- Started treating the dashboard as a real hosted product rather than assuming users would tolerate local-dev style fallback states.

### Why this release matters
- This release made the dashboard significantly less confusing during cold starts and reconnects.

## v1.1.3 - 2026-03-24

### Fixed
- Quieted the telemetry warning for ordinary users who had not configured dashboard telemetry.

### Changed
- Updated public docs and landing copy to reflect npm installation.

### Why this release matters
- This was the point where the CLI started feeling less like an internal operator tool and more like a user-facing installable product.

## v1.1.2 - 2026-03-23

### Added
- Published the npm wrapper under `baselineprod-cli`.

### Fixed
- Matched the npm release line with the packaged GitHub release assets.

### Why this release matters
- This is the release that made Baseline installable from npm for real users.

## v1.1.1 - 2026-03-23

### Fixed
- Fixed Bash release packaging to use absolute archive paths so Windows zip creation succeeds reliably.

### Why this release matters
- This release stabilized the release-packaging path itself and unblocked cross-platform archives.

## v1.1.0 - 2026-03-21

### Added
- Brought together the major auth-first and dashboard-first work into the first substantial `1.1.x` release line.

### Changed
- Expanded the hosted dashboard/auth surface and operational visibility around CLI activity and project scans.
- Improved the frontend and dashboard UX across the auth and settings flows.

### Fixed
- Hardened OIDC redirects, CSRF handling, and legacy auth routes.
- Improved dashboard behavior around API keys, scan visibility, CLI approvals, and frontend/runtime auth configuration.

### Why this release matters
- This is the release where Baseline moved from "CLI plus pieces" into a more complete hosted product shape.

## v1.0.1 - 2026-02-18

### Added
- Follow-up stabilizations on top of the first public `1.0.0` release line.

## v1.0.0 - 2026-02-08

### Added
- Initial `1.0.0` Baseline release line.

