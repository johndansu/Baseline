package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
	if got := normalizeOIDCReturnTo("/signup?from=landing"); got != "/signup?from=landing" {
		t.Fatalf("expected supported relative return_to to be kept, got %q", got)
	}
	if got := normalizeOIDCReturnTo("/dashboard"); got != "/" {
		t.Fatalf("expected unknown relative return_to to fallback to root, got %q", got)
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

func TestLegacyAuthRouteAliasesRedirectToCanonicalPaths(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DashboardSessionEnabled = true
	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	noRedirectClient := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirect blocked for test")
		},
	}

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/login?return_to=%2Fsignup", nil)
	if err != nil {
		t.Fatalf("failed to create /login request: %v", err)
	}
	resp, err := noRedirectClient.Do(req)
	if err != nil && resp == nil {
		t.Fatalf("expected redirect response for /login alias, got error: %v", err)
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	body := string(bodyBytes)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 for /login alias, got %d body=%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Location"); got != "/signin?return_to=%2Fsignup" {
		t.Fatalf("expected /login redirect location, got %q", got)
	}

	req, err = http.NewRequest(http.MethodGet, ts.URL+"/register?return_to=%2F", nil)
	if err != nil {
		t.Fatalf("failed to create /register request: %v", err)
	}
	resp, err = noRedirectClient.Do(req)
	if err != nil && resp == nil {
		t.Fatalf("expected redirect response for /register alias, got error: %v", err)
	}
	bodyBytes, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	body = string(bodyBytes)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 for /register alias, got %d body=%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Location"); got != "/signup?return_to=%2F" {
		t.Fatalf("expected /register redirect location, got %q", got)
	}
}

func TestNewServerOIDCMissingConfigErrorsAreExplicit(t *testing.T) {
	base := DefaultConfig()
	base.OIDCEnabled = true
	base.OIDCIssuerURL = "https://issuer.example.com"
	base.OIDCClientID = "client-id"
	base.OIDCClientSecret = "client-secret"
	base.OIDCRedirectURL = "https://app.example.com/v1/auth/oidc/callback"

	cases := []struct {
		name    string
		mutate  func(*Config)
		wantSub string
	}{
		{
			name: "missing issuer",
			mutate: func(cfg *Config) {
				cfg.OIDCIssuerURL = ""
			},
			wantSub: "issuer URL is not set",
		},
		{
			name: "missing client id",
			mutate: func(cfg *Config) {
				cfg.OIDCClientID = ""
			},
			wantSub: "client ID is not set",
		},
		{
			name: "missing client secret",
			mutate: func(cfg *Config) {
				cfg.OIDCClientSecret = ""
			},
			wantSub: "client secret is not set",
		},
		{
			name: "missing redirect",
			mutate: func(cfg *Config) {
				cfg.OIDCRedirectURL = ""
			},
			wantSub: "redirect URL is not set",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			_, err := NewServer(cfg, nil)
			if err == nil {
				t.Fatalf("expected NewServer to fail for %s", tc.name)
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.wantSub)) {
				t.Fatalf("expected error to contain %q, got %q", tc.wantSub, err.Error())
			}
		})
	}
}

func TestOIDCCallbackProviderErrorIsSanitized(t *testing.T) {
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

	resp, body := mustRequest(
		t,
		http.DefaultClient,
		http.MethodGet,
		ts.URL+"/v1/auth/oidc/callback?error=access_denied&error_description=account+not+found",
		nil,
		nil,
	)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for provider callback error, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"code":"oidc_error"`) {
		t.Fatalf("expected oidc_error code, body=%s", body)
	}
	if strings.Contains(strings.ToLower(body), "account not found") {
		t.Fatalf("expected sanitized provider error message, body=%s", body)
	}
}

func TestOIDCUnavailableMessageDoesNotLeakInternalErrorDetails(t *testing.T) {
	raw := oidcUnavailableMessage(errors.New("dial tcp timeout to internal.provider"))
	if strings.Contains(strings.ToLower(raw), "dial tcp timeout") {
		t.Fatalf("expected sanitized oidc unavailable message, got %q", raw)
	}
}
