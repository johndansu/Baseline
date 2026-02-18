package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/baseline/baseline/internal/api"
	"github.com/baseline/baseline/internal/types"
)

func TestHandleVersion(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	HandleVersion()

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if output == "" {
		t.Error("Expected version output, got empty string")
	}

	if !strings.HasPrefix(strings.TrimSpace(output), "baseline") {
		t.Errorf("Expected output to start with 'baseline', got '%s'", output)
	}
}

func TestRequireGitRepo(t *testing.T) {
	// Test in a non-git directory
	tempDir := t.TempDir()
	oldWd, _ := os.Getwd()
	defer os.Chdir(oldWd)

	os.Chdir(tempDir)
	err := requireGitRepo()
	if err == nil {
		t.Error("Expected error when not in git repo, got nil")
	}

	expectedError := "not a git repository. Baseline must be run from within a git repository"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

func TestRequireGitRepoSuccess(t *testing.T) {
	// Test in a git directory (current repo should be git)
	// Change to root directory which should be a git repo
	oldWd, _ := os.Getwd()
	defer os.Chdir(oldWd)

	// Go to project root (assuming we're in internal/cli)
	os.Chdir("../..")

	err := requireGitRepo()
	if err != nil {
		t.Errorf("Expected no error in git repo, got '%v'", err)
	}
}

func TestHandleExplainUsage(t *testing.T) {
	cmd := exec.Command("go", "run", "../../cmd/baseline", "explain")
	output, err := cmd.CombinedOutput()

	if err == nil {
		t.Fatalf("Expected explain command without args to fail. Output: %s", string(output))
	}

	if !strings.Contains(string(output), "Usage: baseline explain <policy_id>") {
		t.Fatalf("Expected usage output for explain command. Output: %s", string(output))
	}
}

func TestHandleExplainWithPolicyID(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	HandleExplain([]string{"G1"})

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if output == "" {
		t.Error("Expected output for policy explanation, got empty string")
	}

	expectedHeader := "=== POLICY EXPLANATION ==="
	if !strings.Contains(output, expectedHeader) {
		t.Errorf("Expected output to contain '%s', got '%s'", expectedHeader, output)
	}
}

func TestHandleCheckNonGitExitCode(t *testing.T) {
	tempDir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	repoRoot := filepath.Clean(filepath.Join(cwd, "..", ".."))
	binPath := filepath.Join(t.TempDir(), "baseline-test")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	buildCmd := exec.Command("go", "build", "-o", binPath, "./cmd/baseline")
	buildCmd.Dir = repoRoot
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build baseline CLI for test: %v\n%s", err, string(output))
	}

	cmd := exec.Command(binPath, "check")
	cmd.Dir = tempDir

	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected check command to fail outside git repository. Output: %s", string(output))
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected exec.ExitError, got %T", err)
	}
	if exitErr.ExitCode() != types.ExitSystemError {
		t.Fatalf("expected exit code %d, got %d. Output: %s", types.ExitSystemError, exitErr.ExitCode(), string(output))
	}
	if !strings.Contains(string(output), "not a git repository") {
		t.Fatalf("expected non-git error output, got: %s", string(output))
	}
}

func TestHandleReportArgs(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected string
		wantErr  bool
	}{
		{
			name:     "default format",
			args:     []string{},
			expected: "text",
		},
		{
			name:     "json format",
			args:     []string{"--json"},
			expected: "json",
		},
		{
			name:     "sarif format",
			args:     []string{"--sarif"},
			expected: "sarif",
		},
		{
			name:    "unknown flag",
			args:    []string{"--bad"},
			wantErr: true,
		},
		{
			name:    "multiple formats",
			args:    []string{"--json", "--sarif"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format, err := parseReportFormat(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for args %v", tt.args)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseReportFormat returned error: %v", err)
			}
			if format != tt.expected {
				t.Fatalf("expected format %q, got %q", tt.expected, format)
			}
		})
	}
}

func TestBuildGenerationOutcome(t *testing.T) {
	violations := []types.PolicyViolation{
		{PolicyID: types.PolicyCIPipeline, Message: "missing ci", Severity: types.SeverityBlock},
		{PolicyID: types.PolicyDocumentation, Message: "missing docs", Severity: types.SeverityBlock},
		{PolicyID: types.PolicyProtectedBranch, Message: "branch policy", Severity: types.SeverityBlock},
	}

	outcome := buildGenerationOutcome(violations, func(v types.PolicyViolation) string {
		switch v.PolicyID {
		case types.PolicyCIPipeline:
			return ""
		case types.PolicyDocumentation:
			return "README.md"
		default:
			return ""
		}
	})

	if len(outcome.GeneratedFiles) != 1 || outcome.GeneratedFiles[0] != "README.md" {
		t.Fatalf("expected one generated README.md, got %#v", outcome.GeneratedFiles)
	}
	if len(outcome.Failed) != 1 || outcome.Failed[0].PolicyID != types.PolicyCIPipeline {
		t.Fatalf("expected CI violation in failed bucket, got %#v", outcome.Failed)
	}
	if len(outcome.Skipped) != 1 || outcome.Skipped[0].PolicyID != types.PolicyProtectedBranch {
		t.Fatalf("expected protected branch violation in skipped bucket, got %#v", outcome.Skipped)
	}
}

func TestIsAIFixSupported(t *testing.T) {
	supported := []string{
		types.PolicyCIPipeline,
		types.PolicyTestSuite,
		types.PolicyDocumentation,
		types.PolicyDeploymentConfig,
		types.PolicyEnvVariables,
	}
	for _, policyID := range supported {
		if !isAIFixSupported(policyID) {
			t.Fatalf("expected policy %s to be AI-fix supported", policyID)
		}
	}

	unsupported := []string{
		types.PolicyProtectedBranch,
		types.PolicyBackupRecovery,
		types.PolicyRollbackPlan,
	}
	for _, policyID := range unsupported {
		if isAIFixSupported(policyID) {
			t.Fatalf("expected policy %s to be unsupported", policyID)
		}
	}
}

// Test exit code constants
func TestExitCodes(t *testing.T) {
	if types.ExitSuccess != 0 {
		t.Errorf("Expected ExitSuccess to be 0, got %d", types.ExitSuccess)
	}

	if types.ExitBlockingViolation != 20 {
		t.Errorf("Expected ExitBlockingViolation to be 20, got %d", types.ExitBlockingViolation)
	}

	if types.ExitSystemError != 50 {
		t.Errorf("Expected ExitSystemError to be 50, got %d", types.ExitSystemError)
	}
}

func TestVerifyAPIProdConfigPass(t *testing.T) {
	cfg := api.DefaultConfig()
	cfg.Addr = "127.0.0.1:8080"
	cfg.DBPath = "baseline_api.db"
	cfg.APIKeys = map[string]api.Role{
		"admin-key": api.RoleAdmin,
	}
	cfg.CORSAllowedOrigins = []string{"https://dashboard.example.com"}
	cfg.MaxBodyBytes = 1 << 20
	cfg.ShutdownTimeout = 10 * time.Second
	cfg.ReadTimeout = 5 * time.Second
	cfg.WriteTimeout = 5 * time.Second
	cfg.IdleTimeout = 30 * time.Second

	result := verifyAPIProdConfig(cfg, func(_ string) string { return "" })
	if len(result.Errors) != 0 {
		t.Fatalf("expected no errors, got %v", result.Errors)
	}
	if len(result.Warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", result.Warnings)
	}
}

func TestVerifyAPIProdConfigDetectsBlockingIssues(t *testing.T) {
	cfg := api.DefaultConfig()
	cfg.Addr = ":8080"
	cfg.DBPath = ":memory:"
	cfg.APIKeys = map[string]api.Role{}
	cfg.CORSAllowedOrigins = []string{"*", "http://dashboard.example.com"}
	cfg.MaxBodyBytes = 0
	cfg.ShutdownTimeout = 0
	cfg.ReadTimeout = 0
	cfg.WriteTimeout = 0
	cfg.IdleTimeout = 0

	result := verifyAPIProdConfig(cfg, func(key string) string {
		if key == "BASELINE_API_KEY" {
			return "replace-with-admin-key"
		}
		return ""
	})

	if len(result.Errors) == 0 {
		t.Fatal("expected blocking errors, got none")
	}
	joined := strings.Join(result.Errors, "\n")
	expected := []string{
		"persistent file path",
		"CORS wildcard",
		"must use HTTPS",
		"MAX_BODY_BYTES",
		"SHUTDOWN_TIMEOUT",
		"placeholder",
	}
	for _, token := range expected {
		if !strings.Contains(joined, token) {
			t.Fatalf("expected error output to contain %q, got:\n%s", token, joined)
		}
	}
}

func TestVerifyAPIProdConfigWarnings(t *testing.T) {
	cfg := api.DefaultConfig()
	cfg.Addr = "127.0.0.1:8080"
	cfg.DBPath = "baseline_api.db"
	cfg.SelfServiceEnabled = true
	cfg.EnrollmentTokens = map[string]api.Role{
		"token-1": api.RoleViewer,
	}
	cfg.EnrollmentMaxUses = 3
	cfg.EnrollmentTokenTTL = 48 * time.Hour
	cfg.CORSAllowedOrigins = []string{"https://dashboard.example.com"}
	cfg.TrustProxyHeaders = false
	cfg.AIEnabled = true
	cfg.APIKeys = map[string]api.Role{}

	result := verifyAPIProdConfig(cfg, func(_ string) string { return "" })
	if len(result.Errors) != 0 {
		t.Fatalf("expected no blocking errors, got %v", result.Errors)
	}
	if len(result.Warnings) == 0 {
		t.Fatal("expected warnings, got none")
	}
	joined := strings.Join(result.Warnings, "\n")
	expected := []string{
		"Enrollment max uses",
		"Enrollment token TTL",
		"No admin API key",
		"AI advisory endpoints are enabled",
	}
	for _, token := range expected {
		if !strings.Contains(joined, token) {
			t.Fatalf("expected warning output to contain %q, got:\n%s", token, joined)
		}
	}
}

func TestVerifyAPIProdConfigRequiresHTTPSAndSecureSessionCookies(t *testing.T) {
	cfg := api.DefaultConfig()
	cfg.Addr = "0.0.0.0:8080"
	cfg.DBPath = "baseline_api.db"
	cfg.APIKeys = map[string]api.Role{
		"admin-key": api.RoleAdmin,
	}
	cfg.CORSAllowedOrigins = []string{"https://dashboard.example.com"}
	cfg.MaxBodyBytes = 1 << 20
	cfg.ShutdownTimeout = 10 * time.Second
	cfg.ReadTimeout = 5 * time.Second
	cfg.WriteTimeout = 5 * time.Second
	cfg.IdleTimeout = 30 * time.Second
	cfg.TrustProxyHeaders = true
	cfg.DashboardSessionEnabled = true
	cfg.RequireHTTPS = false
	cfg.DashboardSessionCookieSecure = false

	result := verifyAPIProdConfig(cfg, func(_ string) string { return "" })
	if len(result.Errors) == 0 {
		t.Fatal("expected blocking errors, got none")
	}
	joined := strings.Join(result.Errors, "\n")
	if !strings.Contains(joined, "BASELINE_API_REQUIRE_HTTPS") {
		t.Fatalf("expected RequireHTTPS validation error, got:\n%s", joined)
	}
	if !strings.Contains(joined, "BASELINE_API_DASHBOARD_SESSION_COOKIE_SECURE") {
		t.Fatalf("expected secure session cookie validation error, got:\n%s", joined)
	}
}

func TestLoadEnvFileIfPresent(t *testing.T) {
	tempDir := t.TempDir()
	envPath := filepath.Join(tempDir, "api.env")
	content := strings.Join([]string{
		"# comment",
		"BASELINE_API_ADDR=:9090",
		"export BASELINE_API_DB_PATH=prod.db",
		"BASELINE_API_CORS_ALLOWED_ORIGINS=\"https://dashboard.local\"",
	}, "\n")
	if err := os.WriteFile(envPath, []byte(content), 0600); err != nil {
		t.Fatalf("write env file failed: %v", err)
	}

	_ = os.Unsetenv("BASELINE_API_ADDR")
	_ = os.Unsetenv("BASELINE_API_DB_PATH")
	_ = os.Unsetenv("BASELINE_API_CORS_ALLOWED_ORIGINS")
	defer os.Unsetenv("BASELINE_API_ADDR")
	defer os.Unsetenv("BASELINE_API_DB_PATH")
	defer os.Unsetenv("BASELINE_API_CORS_ALLOWED_ORIGINS")

	if err := loadEnvFileIfPresent(envPath); err != nil {
		t.Fatalf("loadEnvFileIfPresent failed: %v", err)
	}

	if got := os.Getenv("BASELINE_API_ADDR"); got != ":9090" {
		t.Fatalf("expected BASELINE_API_ADDR=:9090, got %q", got)
	}
	if got := os.Getenv("BASELINE_API_DB_PATH"); got != "prod.db" {
		t.Fatalf("expected BASELINE_API_DB_PATH=prod.db, got %q", got)
	}
	if got := os.Getenv("BASELINE_API_CORS_ALLOWED_ORIGINS"); got != "https://dashboard.local" {
		t.Fatalf("expected CORS origin to load, got %q", got)
	}
}

func TestLoadEnvFileDoesNotOverrideExistingEnv(t *testing.T) {
	tempDir := t.TempDir()
	envPath := filepath.Join(tempDir, "api.env")
	if err := os.WriteFile(envPath, []byte("BASELINE_API_ADDR=:7000\n"), 0600); err != nil {
		t.Fatalf("write env file failed: %v", err)
	}

	if err := os.Setenv("BASELINE_API_ADDR", ":8000"); err != nil {
		t.Fatalf("set env failed: %v", err)
	}
	defer os.Unsetenv("BASELINE_API_ADDR")

	if err := loadEnvFileIfPresent(envPath); err != nil {
		t.Fatalf("loadEnvFileIfPresent failed: %v", err)
	}
	if got := os.Getenv("BASELINE_API_ADDR"); got != ":8000" {
		t.Fatalf("expected existing env to remain :8000, got %q", got)
	}
}

func TestShouldAutoStartAPIWithConfiguredKey(t *testing.T) {
	t.Setenv("BASELINE_API_KEY", "auto-start-admin-key")
	if !ShouldAutoStartAPI() {
		t.Fatal("expected ShouldAutoStartAPI to return true when BASELINE_API_KEY is set")
	}
}

// Test command routing in main would require more complex setup
// This is covered by integration tests in the main package
