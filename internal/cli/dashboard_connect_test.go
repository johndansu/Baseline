package cli

import (
	"bufio"
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	clitrace "github.com/baseline/baseline/internal/cli/trace"
	"github.com/baseline/baseline/internal/types"
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

func TestMaybePromptForDashboardUploadUsesHostedDefaultWhenNoSessionOrEnv(t *testing.T) {
	repoDir := setupTempGitRepo(t, "https://github.com/example/baseline.git")
	configPath := filepath.Join(repoDir, ".baseline", "config.yaml")
	t.Setenv("BASELINE_CONFIG_PATH", configPath)

	stdinFile := tempInputFile(t, "y\n")
	defer stdinFile.Close()
	stdoutFile, err := os.CreateTemp(t.TempDir(), "baseline-dashboard-output-*.txt")
	if err != nil {
		t.Fatalf("create stdout file: %v", err)
	}
	defer stdoutFile.Close()

	oldCheck := interactiveTerminalCheck
	interactiveTerminalCheck = func(stdin *os.File, stdout *os.File) bool { return true }
	defer func() { interactiveTerminalCheck = oldCheck }()

	oldBrowserConnect := connectDashboardViaBrowser
	connectDashboardViaBrowser = func(traceCtx *clitrace.Context, apiBaseURL, explicitProjectID string, stdout *os.File) (dashboardConnectResult, error) {
		if apiBaseURL != defaultHostedDashboardAPIURL {
			t.Fatalf("expected hosted default API URL %q, got %q", defaultHostedDashboardAPIURL, apiBaseURL)
		}
		return dashboardConnectResult{
			APIBaseURL: apiBaseURL,
			ProjectID:  "proj_hosted_default",
		}, nil
	}
	defer func() { connectDashboardViaBrowser = oldBrowserConnect }()

	connection, err := maybePromptForDashboardUpload(stdinFile, stdoutFile)
	if err != nil {
		t.Fatalf("maybePromptForDashboardUpload returned error: %v", err)
	}
	if connection.APIBaseURL != defaultHostedDashboardAPIURL {
		t.Fatalf("expected hosted default API URL %q, got %q", defaultHostedDashboardAPIURL, connection.APIBaseURL)
	}
	if connection.ProjectID != "proj_hosted_default" {
		t.Fatalf("expected hosted default project id, got %q", connection.ProjectID)
	}
}

func TestMaybePromptForDashboardUploadUsesStoredSessionWithoutManualAPIKey(t *testing.T) {
	repoDir := setupTempGitRepo(t, "https://github.com/example/baseline.git")
	configPath := filepath.Join(repoDir, ".baseline", "config.yaml")
	t.Setenv("BASELINE_CONFIG_PATH", configPath)

	var authHeaders []string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"projects":[{"id":"proj_session","name":"baseline","repository_url":"https://github.com/example/baseline.git"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	if err := saveStoredDashboardCLISession(baselineDashboardCLISession{
		APIBaseURL:  server.URL,
		AccessToken: "session-access-token",
	}); err != nil {
		t.Fatalf("saveStoredDashboardCLISession: %v", err)
	}

	stdinFile := tempInputFile(t, "y\n")
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
	if connection.APIBaseURL != server.URL {
		t.Fatalf("expected API base URL %q, got %q", server.URL, connection.APIBaseURL)
	}
	if connection.ProjectID != "proj_session" {
		t.Fatalf("expected project proj_session, got %q", connection.ProjectID)
	}
	if connection.APIKey != "" {
		t.Fatalf("expected no fallback API key for session-backed prompt, got %q", connection.APIKey)
	}
	if len(authHeaders) != 1 || authHeaders[0] != "Bearer session-access-token" {
		t.Fatalf("expected session token to be used for project lookup, got %#v", authHeaders)
	}

	savedConfig, err := loadBaselineLocalConfig()
	if err != nil {
		t.Fatalf("loadBaselineLocalConfig returned error: %v", err)
	}
	if savedConfig.Dashboard.Upload.APIKeyRef != "" {
		t.Fatalf("expected session-backed upload config without API key ref, got %q", savedConfig.Dashboard.Upload.APIKeyRef)
	}
}

func TestMaybePromptForDashboardUploadPrefersStoredSessionAPIOverLocalEnv(t *testing.T) {
	repoDir := setupTempGitRepo(t, "https://github.com/example/baseline.git")
	configPath := filepath.Join(repoDir, ".baseline", "config.yaml")
	t.Setenv("BASELINE_CONFIG_PATH", configPath)
	t.Setenv("BASELINE_API_ADDR", "127.0.0.1:8080")
	t.Setenv("BASELINE_API_KEY", "local-dev-key")

	var authHeaders []string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"projects":[{"id":"proj_hosted","name":"baseline","repository_url":"https://github.com/example/baseline.git"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	if err := saveStoredDashboardCLISession(baselineDashboardCLISession{
		APIBaseURL:  server.URL,
		AccessToken: "session-access-token",
	}); err != nil {
		t.Fatalf("saveStoredDashboardCLISession: %v", err)
	}

	stdinFile := tempInputFile(t, "y\n")
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
	if connection.APIBaseURL != server.URL {
		t.Fatalf("expected hosted session API base URL %q, got %q", server.URL, connection.APIBaseURL)
	}
	if connection.ProjectID != "proj_hosted" {
		t.Fatalf("expected project proj_hosted, got %q", connection.ProjectID)
	}
	if connection.APIKey != "" {
		t.Fatalf("expected no fallback API key for session-backed prompt, got %q", connection.APIKey)
	}
	if len(authHeaders) != 1 || authHeaders[0] != "Bearer session-access-token" {
		t.Fatalf("expected hosted session token to be used, got %#v", authHeaders)
	}
}

func TestConnectDashboardForCurrentProjectWithReaderReturnsHelpfulErrorWhenBrowserConnectFails(t *testing.T) {
	repoDir := setupTempGitRepo(t, "https://github.com/example/baseline.git")
	configPath := filepath.Join(repoDir, ".baseline", "config.yaml")
	t.Setenv("BASELINE_CONFIG_PATH", configPath)

	reader := bufio.NewReader(strings.NewReader(""))
	stdoutFile, err := os.CreateTemp(t.TempDir(), "baseline-dashboard-output-*.txt")
	if err != nil {
		t.Fatalf("create stdout file: %v", err)
	}
	defer stdoutFile.Close()

	_, err = connectDashboardForCurrentProjectWithReader(nil, dashboardConnectOptions{
		APIBaseURL: "https://baseline-api.example.com",
	}, reader, stdoutFile, true)
	if err == nil {
		t.Fatal("expected browser connect failure")
	}
	if !strings.Contains(err.Error(), "dashboard browser connect failed") {
		t.Fatalf("expected browser connect failure guidance, got %q", err.Error())
	}
	if strings.Contains(err.Error(), "Falling back to manual API key entry") {
		t.Fatalf("did not expect manual fallback guidance, got %q", err.Error())
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

func TestShouldResetDashboardSavedConnection(t *testing.T) {
	connection := dashboardConnectionConfig{
		Enabled:  true,
		Prompted: true,
		Source:   "saved",
	}

	if !shouldResetDashboardSavedConnection(connection, errors.New("project lookup rejected with status 401")) {
		t.Fatal("expected 401 saved connection failure to reset stored dashboard connection")
	}
	if !shouldResetDashboardSavedConnection(connection, errors.New("upload rejected with status 403")) {
		t.Fatal("expected 403 saved connection failure to reset stored dashboard connection")
	}
	if shouldResetDashboardSavedConnection(connection, errors.New("no projects found in API")) {
		t.Fatal("did not expect non-auth saved connection failure to reset stored dashboard connection")
	}
	if shouldResetDashboardSavedConnection(dashboardConnectionConfig{Source: "flags"}, errors.New("upload rejected with status 401")) {
		t.Fatal("did not expect flag-based connection failure to reset stored dashboard connection")
	}
}

func TestResetSavedDashboardConnectionClearsConfigAndSecret(t *testing.T) {
	repoDir := setupTempGitRepo(t, "https://github.com/example/baseline.git")
	configPath := filepath.Join(repoDir, ".baseline", "config.yaml")
	t.Setenv("BASELINE_CONFIG_PATH", configPath)

	cfg := baselineLocalConfig{
		Dashboard: baselineDashboardConfig{
			Upload: dashboardUploadConfig{
				Prompted:   true,
				Enabled:    true,
				APIBaseURL: "http://127.0.0.1:8080",
				ProjectID:  "proj_saved",
				APIKeyRef:  "default",
			},
		},
	}
	if err := saveBaselineLocalConfig(cfg); err != nil {
		t.Fatalf("saveBaselineLocalConfig: %v", err)
	}
	secrets := baselineSecrets{
		Dashboard: baselineDashboardSecrets{
			APIKeys: map[string]string{
				"default": "revoked-key",
			},
		},
	}
	if err := saveBaselineSecrets(secrets); err != nil {
		t.Fatalf("saveBaselineSecrets: %v", err)
	}

	if err := resetSavedDashboardConnection(); err != nil {
		t.Fatalf("resetSavedDashboardConnection returned error: %v", err)
	}

	savedConfig, err := loadBaselineLocalConfig()
	if err != nil {
		t.Fatalf("loadBaselineLocalConfig: %v", err)
	}
	if savedConfig.Dashboard.Upload.Prompted || savedConfig.Dashboard.Upload.Enabled || savedConfig.Dashboard.Upload.APIKeyRef != "" {
		t.Fatalf("expected cleared saved dashboard upload config, got %+v", savedConfig.Dashboard.Upload)
	}

	savedSecrets, err := loadBaselineSecrets()
	if err != nil {
		t.Fatalf("loadBaselineSecrets: %v", err)
	}
	if got := savedSecrets.Dashboard.APIKeys["default"]; got != "" {
		t.Fatalf("expected saved dashboard API key to be removed, got %q", got)
	}
}

func TestRunDashboardConnectCommandHelp(t *testing.T) {
	traceCtx := clitrace.Start("dashboard connect")

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = oldStdout
	}()

	result := runDashboardConnectCommand(traceCtx, dashboardConnectionConfig{}, []string{"--help"})

	_ = w.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)

	if result.ExitCode != types.ExitSuccess {
		t.Fatalf("expected help exit code %d, got %d", types.ExitSuccess, result.ExitCode)
	}
	if !strings.Contains(buf.String(), "Usage: baseline dashboard connect") {
		t.Fatalf("expected dashboard connect usage output, got %q", buf.String())
	}
	foundBranch := false
	for _, event := range traceCtx.Events() {
		if event.Type == "cli_branch_taken" && event.Branch == "help_requested" {
			foundBranch = true
			break
		}
	}
	if !foundBranch {
		t.Fatal("expected help_requested trace branch for dashboard connect")
	}
}

func TestRunDashboardConnectCommandRecordsProjectResolutionAndPersistenceHelpers(t *testing.T) {
	repoDir := setupTempGitRepo(t, "https://github.com/example/baseline.git")
	configPath := filepath.Join(repoDir, ".baseline", "config.yaml")
	t.Setenv("BASELINE_CONFIG_PATH", configPath)

	var authHeaders []string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"projects":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/projects":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"proj_baseline","name":"baseline","repository_url":"https://github.com/example/baseline.git"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	traceCtx := clitrace.Start("dashboard connect")
	result := runDashboardConnectCommand(traceCtx, dashboardConnectionConfig{}, []string{"--api", server.URL, "--api-key", "test-api-key"})
	if result.ExitCode != types.ExitSuccess {
		t.Fatalf("expected success exit code %d, got %d", types.ExitSuccess, result.ExitCode)
	}
	if len(authHeaders) != 2 {
		t.Fatalf("expected project lookup/create to use API key, got %#v", authHeaders)
	}

	foundProjectResolution := false
	foundConfigSave := false
	foundSecretsSave := false
	for _, event := range traceCtx.Events() {
		if event.Type == "cli_helper_exited" && event.Function == "resolveOrCreateProjectForConnection" && event.Status == "ok" {
			foundProjectResolution = true
		}
		if event.Type == "cli_helper_exited" && event.Function == "saveBaselineLocalConfig" && event.Status == "ok" {
			foundConfigSave = true
		}
		if event.Type == "cli_helper_exited" && event.Function == "saveBaselineSecrets" && event.Status == "ok" {
			foundSecretsSave = true
		}
	}
	if !foundProjectResolution {
		t.Fatal("expected resolveOrCreateProjectForConnection helper exit trace event for dashboard connect")
	}
	if !foundConfigSave {
		t.Fatal("expected saveBaselineLocalConfig helper exit trace event for dashboard connect")
	}
	if !foundSecretsSave {
		t.Fatal("expected saveBaselineSecrets helper exit trace event for dashboard connect")
	}
}

func TestConnectDashboardForCurrentProjectWithReaderUsesBrowserLoginWhenNoSessionOrAPIKey(t *testing.T) {
	repoDir := setupTempGitRepo(t, "https://github.com/example/baseline.git")
	configPath := filepath.Join(repoDir, ".baseline", "config.yaml")
	t.Setenv("BASELINE_CONFIG_PATH", configPath)

	var openedURL string
	oldOpenBrowser := openBrowserForDashboardLogin
	openBrowserForDashboardLogin = func(target string) error {
		openedURL = target
		return nil
	}
	defer func() { openBrowserForDashboardLogin = oldOpenBrowser }()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/cli/session/start":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{
				"device_code":"device-123",
				"user_code":"ABCD-EFGH",
				"verification_url":"` + server.URL + `/cli-login.html",
				"complete_verification_url":"` + server.URL + `/cli-login.html?device_code=device-123&user_code=ABCD-EFGH",
				"expires_at":"2099-03-16T21:30:00Z",
				"interval_seconds":1
			}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/cli/session/poll":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"access_token":"session-access-token",
				"refresh_token":"session-refresh-token",
				"user":"John",
				"email":"john@example.com",
				"role":"admin"
			}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"projects":[{"id":"proj_browser","name":"baseline","repository_url":"https://github.com/example/baseline.git"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	reader := bufio.NewReader(strings.NewReader(""))
	stdoutFile, err := os.CreateTemp(t.TempDir(), "baseline-dashboard-output-*.txt")
	if err != nil {
		t.Fatalf("create stdout file: %v", err)
	}
	defer stdoutFile.Close()

	result, err := connectDashboardForCurrentProjectWithReader(nil, dashboardConnectOptions{
		APIBaseURL: server.URL,
	}, reader, stdoutFile, true)
	if err != nil {
		t.Fatalf("connectDashboardForCurrentProjectWithReader returned error: %v", err)
	}
	if result.APIBaseURL != server.URL {
		t.Fatalf("expected API base URL %q, got %q", server.URL, result.APIBaseURL)
	}
	if result.ProjectID != "proj_browser" {
		t.Fatalf("expected project proj_browser, got %q", result.ProjectID)
	}
	if !strings.Contains(openedURL, "/cli-login.html?device_code=device-123&user_code=") {
		t.Fatalf("expected browser approval URL to be opened, got %q", openedURL)
	}

	savedSession := loadStoredDashboardCLISession()
	if savedSession.APIBaseURL != server.URL || savedSession.AccessToken != "session-access-token" {
		t.Fatalf("expected stored CLI session after browser login, got %+v", savedSession)
	}
}

func TestRunDashboardDisconnectCommandClearsSavedConnection(t *testing.T) {
	repoDir := setupTempGitRepo(t, "https://github.com/example/baseline.git")
	configPath := filepath.Join(repoDir, ".baseline", "config.yaml")
	t.Setenv("BASELINE_CONFIG_PATH", configPath)

	cfg := baselineLocalConfig{
		Dashboard: baselineDashboardConfig{
			Upload: dashboardUploadConfig{
				Prompted:   true,
				Enabled:    true,
				APIBaseURL: "http://127.0.0.1:8080",
				ProjectID:  "proj_saved",
				APIKeyRef:  "default",
			},
		},
	}
	if err := saveBaselineLocalConfig(cfg); err != nil {
		t.Fatalf("saveBaselineLocalConfig: %v", err)
	}
	secrets := baselineSecrets{
		Dashboard: baselineDashboardSecrets{
			APIKeys: map[string]string{
				"default": "revoked-key",
			},
		},
	}
	if err := saveBaselineSecrets(secrets); err != nil {
		t.Fatalf("saveBaselineSecrets: %v", err)
	}

	traceCtx := clitrace.Start("dashboard disconnect")
	result := runDashboardDisconnectCommand(traceCtx, dashboardConnectionConfig{}, nil)
	if result.ExitCode != types.ExitSuccess {
		t.Fatalf("expected success exit code %d, got %d", types.ExitSuccess, result.ExitCode)
	}

	savedConfig, err := loadBaselineLocalConfig()
	if err != nil {
		t.Fatalf("loadBaselineLocalConfig: %v", err)
	}
	if savedConfig.Dashboard.Upload.Prompted || savedConfig.Dashboard.Upload.Enabled || savedConfig.Dashboard.Upload.APIKeyRef != "" {
		t.Fatalf("expected cleared saved dashboard upload config, got %+v", savedConfig.Dashboard.Upload)
	}
}

func TestParseBaselineLocalConfigSupportsLegacyValuesContainingColon(t *testing.T) {
	content := []byte(`# Baseline Configuration
# This file configures Baseline policy enforcement

policy_set = "baseline:prod"
enforcement_mode = "audit"
`)

	cfg, err := parseBaselineLocalConfig(content)
	if err != nil {
		t.Fatalf("parseBaselineLocalConfig: %v", err)
	}
	if cfg.PolicySet != "baseline:prod" {
		t.Fatalf("expected policy_set baseline:prod, got %q", cfg.PolicySet)
	}
	if cfg.EnforcementMode != "audit" {
		t.Fatalf("expected enforcement_mode audit, got %q", cfg.EnforcementMode)
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
