package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveDashboardUploadConfigForScanPrefersSavedDisabledConfigOverEnv(t *testing.T) {
	repoDir := setupTempGitRepo(t, "https://github.com/example/baseline.git")
	configPath := filepath.Join(repoDir, ".baseline", "config.yaml")
	t.Setenv("BASELINE_CONFIG_PATH", configPath)
	t.Setenv("BASELINE_API_ADDR", "127.0.0.1:8080")
	t.Setenv("BASELINE_API_KEY", "env-api-key")

	cfg := baselineLocalConfig{
		Dashboard: baselineDashboardConfig{
			Upload: dashboardUploadConfig{
				Prompted: true,
				Enabled:  false,
			},
		},
	}
	if err := saveBaselineLocalConfig(cfg); err != nil {
		t.Fatalf("saveBaselineLocalConfig: %v", err)
	}

	connection, err := resolveDashboardUploadConfigForScan(scanCommandOptions{})
	if err != nil {
		t.Fatalf("resolveDashboardUploadConfigForScan returned error: %v", err)
	}
	if !connection.Prompted {
		t.Fatalf("expected prompted config to be returned")
	}
	if connection.Enabled {
		t.Fatalf("expected disabled dashboard upload, got enabled config: %+v", connection)
	}
	if connection.APIBaseURL != "" || connection.ProjectID != "" || connection.APIKey != "" {
		t.Fatalf("expected disabled config to suppress upload details, got %+v", connection)
	}
}

func TestMaybePromptForDashboardUploadConnectsAndPersistsConfig(t *testing.T) {
	repoDir := setupTempGitRepo(t, "https://github.com/example/baseline.git")
	configPath := filepath.Join(repoDir, ".baseline", "config.yaml")
	t.Setenv("BASELINE_CONFIG_PATH", configPath)

	var authHeaders []string
	var createdProjectName string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"projects":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/projects":
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode create project payload: %v", err)
			}
			createdProjectName, _ = payload["name"].(string)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"proj_baseline","name":"baseline","repository_url":"https://github.com/example/baseline.git"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	parsedURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	t.Setenv("BASELINE_API_ADDR", parsedURL.Host)

	stdinFile := tempInputFile(t, "y\n\nuser-api-key\n")
	defer stdinFile.Close()
	stdoutFile, err := os.CreateTemp(t.TempDir(), "baseline-dashboard-output-*.txt")
	if err != nil {
		t.Fatalf("create stdout file: %v", err)
	}
	defer stdoutFile.Close()

	oldCheck := interactiveTerminalCheck
	interactiveTerminalCheck = func(stdin *os.File, stdout *os.File) bool { return true }
	defer func() { interactiveTerminalCheck = oldCheck }()

	connection, err := maybePromptForDashboardUpload(stdinFile, stdoutFile)
	if err != nil {
		t.Fatalf("maybePromptForDashboardUpload returned error: %v", err)
	}
	if !connection.Enabled || !connection.Prompted {
		t.Fatalf("expected enabled prompted connection, got %+v", connection)
	}
	if connection.APIBaseURL != server.URL {
		t.Fatalf("expected API base URL %q, got %q", server.URL, connection.APIBaseURL)
	}
	if connection.ProjectID != "proj_baseline" {
		t.Fatalf("expected project proj_baseline, got %q", connection.ProjectID)
	}
	if connection.APIKey != "user-api-key" {
		t.Fatalf("expected stored API key to be returned, got %q", connection.APIKey)
	}
	if connection.Source != "prompt" {
		t.Fatalf("expected prompt connection source, got %q", connection.Source)
	}
	if len(authHeaders) != 2 || authHeaders[0] != "Bearer user-api-key" || authHeaders[1] != "Bearer user-api-key" {
		t.Fatalf("expected project lookup/create to use provided key, got %#v", authHeaders)
	}
	if strings.TrimSpace(createdProjectName) == "" {
		t.Fatalf("expected create project payload to include a name")
	}

	savedConfig, err := loadBaselineLocalConfig()
	if err != nil {
		t.Fatalf("loadBaselineLocalConfig returned error: %v", err)
	}
	if !savedConfig.Dashboard.Upload.Prompted || !savedConfig.Dashboard.Upload.Enabled {
		t.Fatalf("expected persisted enabled upload config, got %+v", savedConfig.Dashboard.Upload)
	}
	if savedConfig.Dashboard.Upload.ProjectID != "proj_baseline" {
		t.Fatalf("expected persisted project ID proj_baseline, got %q", savedConfig.Dashboard.Upload.ProjectID)
	}
	if savedConfig.Dashboard.Upload.APIKeyRef != "default" {
		t.Fatalf("expected persisted API key ref default, got %q", savedConfig.Dashboard.Upload.APIKeyRef)
	}

	secrets, err := loadBaselineSecrets()
	if err != nil {
		t.Fatalf("loadBaselineSecrets returned error: %v", err)
	}
	if got := secrets.Dashboard.APIKeys["default"]; got != "user-api-key" {
		t.Fatalf("expected stored API key, got %q", got)
	}
}

func TestFormatDashboardUploadFailureSuggestsRepairForSavedConnection(t *testing.T) {
	connection := dashboardConnectionConfig{
		Enabled:  true,
		Prompted: true,
		Source:   "saved",
	}

	message := formatDashboardUploadFailure(connection, errors.New("project lookup rejected with status 403"))
	if !strings.Contains(message, "Run `baseline dashboard connect` to repair this project connection.") {
		t.Fatalf("expected repair guidance, got %q", message)
	}
}

func TestFormatDashboardUploadFailureKeepsRawMessageForNonSavedConnection(t *testing.T) {
	connection := dashboardConnectionConfig{
		Enabled:  true,
		Prompted: true,
		Source:   "flags",
	}

	message := formatDashboardUploadFailure(connection, errors.New("project lookup rejected with status 403"))
	if strings.Contains(message, "repair this project connection") {
		t.Fatalf("did not expect repair guidance for non-saved connection, got %q", message)
	}
	if !strings.Contains(message, "API upload failed: project lookup rejected with status 403") {
		t.Fatalf("expected raw failure message, got %q", message)
	}
}

func setupTempGitRepo(t *testing.T, remoteURL string) string {
	t.Helper()

	repoDir := t.TempDir()
	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(repoDir); err != nil {
		t.Fatalf("chdir temp repo: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalWD)
	})

	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repoDir
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
		}
	}

	runGit("init", "-q")
	runGit("remote", "add", "origin", remoteURL)
	return repoDir
}

func tempInputFile(t *testing.T, content string) *os.File {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), "baseline-dashboard-input-*.txt")
	if err != nil {
		t.Fatalf("create temp input file: %v", err)
	}
	if _, err := file.WriteString(content); err != nil {
		t.Fatalf("write temp input file: %v", err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatalf("seek temp input file: %v", err)
	}
	return file
}
