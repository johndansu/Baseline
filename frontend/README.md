# Frontend Development Mode

This folder is static frontend with optional live API integration.

- Open `frontend/index.html` directly in your browser.
- Dashboard UI has been removed during auth-first reset.
- For live auth testing, run the API server:
  - `baseline api serve --addr :8080`
  - use `http://127.0.0.1:8080/signin.html` or `http://127.0.0.1:8080/signup.html`

Important:
- Static/proxy use is best treated as preview mode while auth flow is stabilized.
- The supported human auth flow (signin/signup -> OIDC -> Baseline session cookie) is API-hosted on `http://127.0.0.1:8080`.
- Use `http://127.0.0.1:8080/signin.html` and `http://127.0.0.1:8080/signup.html` for login/session testing.

The pages use:

- `frontend/styles.css`
- `frontend/app.js`
- `frontend/auth.js`
- `img/baseline logo.png` as the header logo
