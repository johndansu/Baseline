# CLI Dashboard Session Auth Plan

## Goal

Create a seamless connection between the admin dashboard and the CLI without relying on long-lived API keys.

The CLI should be able to use the same signed-in identity as the dashboard through a short-lived, revocable session flow.

## What We Want

- no copied API keys
- no pasted bearer tokens
- no manual secret juggling
- CLI auth tied to the real dashboard user
- admin role and permissions inherited from the dashboard account
- easy revoke and rotation
- auditable CLI session activity

## Recommended Model

Use a browser-assisted CLI session flow, similar to a device login flow.

### User experience

1. User runs:
   - `baseline dashboard login`
2. CLI opens a browser or prints an approval URL.
3. User approves the CLI from the already signed-in dashboard session.
4. API returns a short-lived CLI access token plus a refresh token.
5. CLI stores the session locally.
6. Future CLI commands use the stored session automatically.

## Why Not API Keys

API keys are the wrong primary auth model for this use case because:

- they are long-lived
- they are easy to leak or over-share
- they are detached from active user session state
- they make “sign in once” clumsy
- they are harder to revoke per device/session cleanly

API keys should remain a fallback for automation, not the default for human CLI usage.

## Architecture

### New backend endpoints

- `POST /v1/cli/session/start`
  - starts a pending CLI login
  - returns:
    - `device_code`
    - `user_code`
    - `verification_url`
    - `expires_at`

- `POST /v1/cli/session/approve`
  - approved from the dashboard by an authenticated browser session
  - binds the pending CLI login to the current user

- `POST /v1/cli/session/poll`
  - CLI polls for approval
  - on success returns:
    - short-lived CLI access token
    - refresh token
    - expiry
    - user/role summary

- `POST /v1/cli/session/refresh`
  - rotates expired or near-expiry CLI access tokens

- `DELETE /v1/cli/session`
  - revokes the local CLI session

### Backend storage

Add tables or equivalent store models for:

- pending CLI auth requests
- active CLI sessions
- refresh tokens or hashed refresh material

Suggested fields:

- session id
- user id
- email
- role
- created at
- approved at
- expires at
- last used at
- revoked at
- client name / host metadata

## CLI Changes

### New commands

- `baseline dashboard login`
- `baseline dashboard logout`
- `baseline dashboard whoami`

### CLI behavior

Commands should prefer auth in this order:

1. active CLI session
2. explicit flags
3. API key fallback

This applies to:

- scan upload
- CLI telemetry
- dashboard connect/status/disconnect
- future admin-aware CLI actions

### Local storage

Store CLI session material in local secrets storage, separate from browser state.

Do not store:

- browser cookies
- Supabase browser localStorage tokens
- raw dashboard session cookies copied from the browser

## Dashboard Changes

### Admin/account UI

Add a simple page or modal for:

- approving pending CLI login
- seeing active CLI sessions
- revoking CLI sessions

Useful data to show:

- device/session label
- created time
- last used time
- role
- revoke button

## Security Requirements

- short-lived access token
- refresh token rotation
- server-side revocation
- role pulled from persisted user/session state
- all session material stored hashed where appropriate
- audit events for:
  - session started
  - session approved
  - session refreshed
  - session revoked

## Traceability Impact

This model improves traceability because:

- CLI actions map to a real user identity
- admin can see who approved and used a CLI session
- role changes can take effect without reissuing API keys
- revoked CLI sessions can cut off future CLI activity cleanly

## Migration Strategy

### Phase 1

Build the CLI session flow alongside API keys.

### Phase 2

Make CLI prefer session auth over API keys automatically.

### Phase 3

Keep API keys only for:

- automation
- CI
- service integrations

## Blunt Assessment

If the goal is a seamless admin dashboard to CLI connection, API keys are the wrong default.

The right solution is a short-lived, browser-approved CLI session flow.

That gives us:

- better UX
- better security
- better revocation
- better auditability

## Recommended Next Step

Implement phase 1:

1. backend CLI session start/approve/poll endpoints
2. `baseline dashboard login`
3. local CLI session storage
4. make telemetry and scan upload use the CLI session first
