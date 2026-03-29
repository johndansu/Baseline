package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestRefreshCLIUploadConnectionUsesLatestStoredSessionToken(t *testing.T) {
	repoDir := setupTempGitRepo(t, "https://github.com/example/baseline.git")
	configPath := filepath.Join(repoDir, ".baseline", "config.yaml")
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
		if payload["refresh_token"] != "refresh-token" {
			t.Fatalf("expected stored refresh token, got %#v", payload["refresh_token"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"access_token":"fresh-token",
			"refresh_token":"refresh-token-rotated",
			"user":"John",
			"email":"john@example.com",
			"role":"admin"
		}`))
	}))
	defer server.Close()

	if err := saveStoredDashboardCLISession(baselineDashboardCLISession{
		APIBaseURL:   server.URL,
		AccessToken:  "stale-token",
		RefreshToken: "refresh-token",
	}); err != nil {
		t.Fatalf("saveStoredDashboardCLISession: %v", err)
	}

	connection := refreshCLIUploadConnection(dashboardConnectionConfig{
		APIBaseURL:  server.URL,
		AccessToken: "stale-token",
	})

	if connection.AccessToken != "fresh-token" {
		t.Fatalf("expected refreshed access token, got %q", connection.AccessToken)
	}

	saved := loadStoredDashboardCLISession()
	if saved.AccessToken != "fresh-token" || saved.RefreshToken != "refresh-token-rotated" {
		t.Fatalf("expected refreshed session to persist, got %+v", saved)
	}
}
