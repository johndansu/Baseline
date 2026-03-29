package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	clitrace "github.com/baseline/baseline/internal/cli/trace"
	"github.com/baseline/baseline/internal/types"
)

func TestAuthTokenForBaseURLRefreshesStoredCLISession(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), ".baseline", "config.yaml")
	t.Setenv("BASELINE_CONFIG_PATH", configPath)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/cli/session/refresh" {
			http.NotFound(w, r)
			return
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode refresh payload: %v", err)
		}
		if payload["refresh_token"] != "refresh-old" {
			t.Fatalf("expected stored refresh token, got %#v", payload["refresh_token"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"access_token":"access-new",
			"refresh_token":"refresh-new",
			"user":"John",
			"email":"john@example.com",
			"role":"admin"
		}`))
	}))
	defer server.Close()

	if err := saveStoredDashboardCLISession(baselineDashboardCLISession{
		APIBaseURL:   server.URL,
		AccessToken:  "access-old",
		RefreshToken: "refresh-old",
	}); err != nil {
		t.Fatalf("saveStoredDashboardCLISession: %v", err)
	}

	token := authTokenForBaseURL(server.URL, "")
	if token != "access-new" {
		t.Fatalf("expected refreshed access token, got %q", token)
	}

	saved := loadStoredDashboardCLISession()
	if saved.AccessToken != "access-new" || saved.RefreshToken != "refresh-new" {
		t.Fatalf("expected refreshed session to persist, got %+v", saved)
	}
}

func TestRunDashboardLogoutCommandClearsStoredCLISession(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), ".baseline", "config.yaml")
	t.Setenv("BASELINE_CONFIG_PATH", configPath)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/v1/cli/session" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"revoked":true}`))
	}))
	defer server.Close()

	if err := saveStoredDashboardCLISession(baselineDashboardCLISession{
		APIBaseURL:  server.URL,
		AccessToken: "access-token",
	}); err != nil {
		t.Fatalf("saveStoredDashboardCLISession: %v", err)
	}

	traceCtx := clitrace.Start("dashboard logout")
	result := runDashboardLogoutCommand(traceCtx, nil)
	if result.ExitCode != types.ExitSuccess {
		t.Fatalf("expected success exit code, got %d", result.ExitCode)
	}

	saved := loadStoredDashboardCLISession()
	if saved.APIBaseURL != "" || saved.AccessToken != "" || saved.RefreshToken != "" {
		t.Fatalf("expected stored CLI session to be cleared, got %+v", saved)
	}
}

func TestActivateDashboardUploadForSessionPersistsSessionBackedConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), ".baseline", "config.yaml")
	t.Setenv("BASELINE_CONFIG_PATH", configPath)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"projects":[{"id":"proj_session","name":"Baseline"}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/projects":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"proj_session","name":"Baseline","default_branch":"main","policy_set":"baseline:prod"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	if err := activateDashboardUploadForSession(server.URL, "session-access-token"); err != nil {
		t.Fatalf("activateDashboardUploadForSession: %v", err)
	}

	cfg, err := loadBaselineLocalConfig()
	if err != nil {
		t.Fatalf("loadBaselineLocalConfig: %v", err)
	}
	if !cfg.Dashboard.Upload.Prompted || !cfg.Dashboard.Upload.Enabled {
		t.Fatalf("expected activated dashboard upload config, got %+v", cfg.Dashboard.Upload)
	}
	if cfg.Dashboard.Upload.APIBaseURL != server.URL {
		t.Fatalf("expected API URL %q, got %q", server.URL, cfg.Dashboard.Upload.APIBaseURL)
	}
	if cfg.Dashboard.Upload.ProjectID != "proj_session" {
		t.Fatalf("expected project id proj_session, got %q", cfg.Dashboard.Upload.ProjectID)
	}
	if cfg.Dashboard.Upload.APIKeyRef != "" {
		t.Fatalf("expected session-backed config without API key ref, got %q", cfg.Dashboard.Upload.APIKeyRef)
	}
}

func TestStartCLISessionLoginUsesServerProvidedCompleteVerificationURL(t *testing.T) {
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/cli/session/start" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{
			"device_code":"device-123",
			"user_code":"ABCD-EFGH",
			"verification_url":"` + serverURL + `/cli-login.html",
			"complete_verification_url":"https://baseline-prod.vercel.app/cli-login.html?device_code=device-123&user_code=ABCD-EFGH",
			"expires_at":"2026-03-16T21:30:00Z",
			"interval_seconds":2
		}`))
	}))
	defer server.Close()
	serverURL = server.URL

	started, err := startCLISessionLogin(server.URL)
	if err != nil {
		t.Fatalf("startCLISessionLogin: %v", err)
	}
	if started.CompleteVerificationURL != "https://baseline-prod.vercel.app/cli-login.html?device_code=device-123&user_code=ABCD-EFGH" {
		t.Fatalf("expected server-provided complete verification URL, got %q", started.CompleteVerificationURL)
	}
}

func TestDefaultDashboardLoginBaseURLFallsBackToHostedDefault(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), ".baseline", "config.yaml")
	t.Setenv("BASELINE_CONFIG_PATH", configPath)
	t.Setenv("BASELINE_SCAN_API_URL", "")
	t.Setenv("BASELINE_API_KEY", "")
	t.Setenv("BASELINE_API_ADDR", "")
	t.Setenv("BASELINE_DASHBOARD_API_URL", "")

	if got := defaultDashboardLoginBaseURL(); got != defaultHostedDashboardAPIURL {
		t.Fatalf("expected hosted default dashboard API URL %q, got %q", defaultHostedDashboardAPIURL, got)
	}
}
