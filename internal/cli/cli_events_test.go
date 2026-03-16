package cli

import (
	"path/filepath"
	"testing"
)

func TestRefreshCLIUploadConnectionUsesLatestStoredSessionToken(t *testing.T) {
	repoDir := setupTempGitRepo(t, "https://github.com/example/baseline.git")
	configPath := filepath.Join(repoDir, ".baseline", "config.yaml")
	t.Setenv("BASELINE_CONFIG_PATH", configPath)

	if err := saveStoredDashboardCLISession(baselineDashboardCLISession{
		APIBaseURL:  "http://127.0.0.1:8080",
		AccessToken: "fresh-token",
	}); err != nil {
		t.Fatalf("saveStoredDashboardCLISession: %v", err)
	}

	connection := refreshCLIUploadConnection(dashboardConnectionConfig{
		APIBaseURL:  "http://127.0.0.1:8080",
		AccessToken: "stale-token",
	})

	if connection.AccessToken != "fresh-token" {
		t.Fatalf("expected latest stored access token, got %q", connection.AccessToken)
	}
}
