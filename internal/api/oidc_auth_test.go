package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthMeWithAPIKey(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{"admin-key": RoleAdmin}

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp, body := mustRequest(t, http.DefaultClient, http.MethodGet, ts.URL+"/v1/auth/me", nil, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.StatusCode, body)
	}
	var payload struct {
		Authenticated bool   `json:"authenticated"`
		Role          Role   `json:"role"`
		AuthSource    string `json:"auth_source"`
		User          string `json:"user"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("unable to parse response: %v body=%s", err, body)
	}
	if !payload.Authenticated || payload.Role != RoleAdmin || payload.AuthSource != "api_key" {
		t.Fatalf("unexpected auth/me payload: %+v", payload)
	}
}

func TestOIDCLoginDisabledReturnsForbidden(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{"admin-key": RoleAdmin}

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp, body := mustRequest(t, http.DefaultClient, http.MethodGet, ts.URL+"/v1/auth/oidc/login", nil, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", resp.StatusCode, body)
	}
}

func TestOIDCEnabledAllowsSessionLookupEndpoint(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OIDCEnabled = true
	cfg.OIDCIssuerURL = "https://issuer.example.com"
	cfg.OIDCClientID = "client-id"
	cfg.OIDCClientSecret = "client-secret"
	cfg.OIDCRedirectURL = "https://app.example.com/v1/auth/oidc/callback"

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp, body := mustRequest(t, http.DefaultClient, http.MethodGet, ts.URL+"/v1/auth/session", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 (no active session), got %d body=%s", resp.StatusCode, body)
	}
}

func TestNewServerOIDCOnlyAuthMechanismAllowed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{}
	cfg.DashboardSessionEnabled = false
	cfg.OIDCEnabled = true
	cfg.OIDCIssuerURL = "https://issuer.example.com"
	cfg.OIDCClientID = "client-id"
	cfg.OIDCClientSecret = "client-secret"
	cfg.OIDCRedirectURL = "https://app.example.com/v1/auth/oidc/callback"

	if _, err := NewServer(cfg, nil); err != nil {
		t.Fatalf("expected OIDC-only config to be accepted, got error: %v", err)
	}
}

func TestIsAuth0Issuer(t *testing.T) {
	if !isAuth0Issuer("https://tenant.auth0.com") {
		t.Fatal("expected auth0 issuer to be detected")
	}
	if isAuth0Issuer("https://accounts.google.com") {
		t.Fatal("did not expect non-auth0 issuer to be detected as auth0")
	}
}

func TestNormalizeOIDCReturnTo(t *testing.T) {
	if got := normalizeOIDCReturnTo("/"); got != "/" {
		t.Fatalf("expected root path, got %q", got)
	}
	if got := normalizeOIDCReturnTo("https://127.0.0.1:8091/"); got != "https://127.0.0.1:8091/" {
		t.Fatalf("expected local absolute return_to to be allowed, got %q", got)
	}
	if got := normalizeOIDCReturnTo("http://localhost:3000/?x=1"); got != "http://localhost:3000/?x=1" {
		t.Fatalf("expected localhost absolute return_to to be allowed, got %q", got)
	}
	if got := normalizeOIDCReturnTo("https://evil.example.com/steal"); got != "/" {
		t.Fatalf("expected non-local absolute return_to to be rejected, got %q", got)
	}
}
