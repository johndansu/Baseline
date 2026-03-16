package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	clitrace "github.com/baseline/baseline/internal/cli/trace"
	"github.com/baseline/baseline/internal/types"
)

func TestRunCheckCommandRecordsErrorTraceOutsideGitRepo(t *testing.T) {
	tempDir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	defer os.Chdir(oldWD)
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}

	traceCtx := clitrace.Start("check")
	result := runCheckCommand(traceCtx, dashboardConnectionConfig{})
	if result.ExitCode != types.ExitSystemError {
		t.Fatalf("expected exit code %d, got %d", types.ExitSystemError, result.ExitCode)
	}

	foundError := false
	for _, event := range traceCtx.Events() {
		if event.Type == "cli_error" && event.Function == "requireGitRepo" {
			foundError = true
			break
		}
	}
	if !foundError {
		t.Fatal("expected cli_error trace event for requireGitRepo")
	}
}

func TestRunScanCommandRecordsHelpBranch(t *testing.T) {
	traceCtx := clitrace.Start("scan")
	result := runScanCommand(traceCtx, dashboardConnectionConfig{}, []string{"--help"})
	if result.ExitCode != types.ExitSuccess {
		t.Fatalf("expected exit code %d, got %d", types.ExitSuccess, result.ExitCode)
	}

	foundBranch := false
	for _, event := range traceCtx.Events() {
		if event.Type == "cli_branch_taken" && event.Branch == "help_requested" {
			foundBranch = true
			break
		}
	}
	if !foundBranch {
		t.Fatal("expected help_requested branch trace event")
	}
}

func TestRunScanCommandRecordsHelperTraceForPromptSkip(t *testing.T) {
	tempDir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	defer os.Chdir(oldWD)
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "README.md"), []byte("# test\n"), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	gitInit := exec.Command("git", "init")
	gitInit.Dir = tempDir
	if output, err := gitInit.CombinedOutput(); err != nil {
		t.Fatalf("git init failed: %v (%s)", err, output)
	}
	t.Setenv("BASELINE_SCAN_API_URL", "")
	t.Setenv("BASELINE_API_ADDR", "")
	t.Setenv("BASELINE_API_KEY", "")

	traceCtx := clitrace.Start("scan")
	result := runScanCommand(traceCtx, dashboardConnectionConfig{}, nil)
	if result.ExitCode != types.ExitSuccess && result.ExitCode != types.ExitBlockingViolation {
		t.Fatalf("expected exit code %d or %d, got %d", types.ExitSuccess, types.ExitBlockingViolation, result.ExitCode)
	}

	foundGenerateKey := false
	foundPromptSkip := false
	for _, event := range traceCtx.Events() {
		if event.Type == "cli_helper_exited" && event.Function == "generateAPIKey" && event.Status == "ok" {
			foundGenerateKey = true
		}
		if event.Type == "cli_helper_exited" && event.Function == "maybePromptForDashboardUpload" && event.Status == "skipped" {
			foundPromptSkip = true
		}
	}
	if !foundGenerateKey {
		t.Fatal("expected generateAPIKey helper exit trace event for scan")
	}
	if !foundPromptSkip {
		t.Fatal("expected maybePromptForDashboardUpload skipped helper exit trace event for scan")
	}
}

func TestRunReportCommandRecordsParseError(t *testing.T) {
	traceCtx := clitrace.Start("report")
	result := runReportCommand(traceCtx, dashboardConnectionConfig{}, []string{"--bad"})
	if result.ExitCode != types.ExitSystemError {
		t.Fatalf("expected exit code %d, got %d", types.ExitSystemError, result.ExitCode)
	}

	foundError := false
	for _, event := range traceCtx.Events() {
		if event.Type == "cli_error" && event.Function == "parseReportFormat" {
			foundError = true
			break
		}
	}
	if !foundError {
		t.Fatal("expected cli_error trace event for parseReportFormat")
	}
}

func TestRunReportCommandRecordsTextOutputHelper(t *testing.T) {
	tempDir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	defer os.Chdir(oldWD)
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "README.md"), []byte("# test\n"), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	gitInit := exec.Command("git", "init")
	gitInit.Dir = tempDir
	if output, err := gitInit.CombinedOutput(); err != nil {
		t.Fatalf("git init failed: %v (%s)", err, output)
	}

	traceCtx := clitrace.Start("report")
	result := runReportCommand(traceCtx, dashboardConnectionConfig{}, nil)
	if result.ExitCode != types.ExitSuccess {
		t.Fatalf("expected exit code %d, got %d", types.ExitSuccess, result.ExitCode)
	}

	foundTextOutput := false
	for _, event := range traceCtx.Events() {
		if event.Type == "cli_helper_exited" && event.Function == "OutputText" && event.Status == "ok" {
			foundTextOutput = true
			break
		}
	}
	if !foundTextOutput {
		t.Fatal("expected OutputText helper exit trace event for report")
	}
}

func TestRunGenerateCommandHelp(t *testing.T) {
	traceCtx := clitrace.Start("generate")

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = oldStdout
	}()

	result := runGenerateCommand(traceCtx, dashboardConnectionConfig{}, []string{"--help"})
	_ = w.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)

	if result.ExitCode != types.ExitSuccess {
		t.Fatalf("expected exit code %d, got %d", types.ExitSuccess, result.ExitCode)
	}
	if buf.Len() == 0 {
		t.Fatal("expected generate usage output")
	}

	foundBranch := false
	for _, event := range traceCtx.Events() {
		if event.Type == "cli_branch_taken" && event.Branch == "help_requested" {
			foundBranch = true
			break
		}
	}
	if !foundBranch {
		t.Fatal("expected help_requested trace event for generate")
	}
}

func TestRunGenerateCommandRecordsGeneratorInitHelper(t *testing.T) {
	tempDir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	defer os.Chdir(oldWD)
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "README.md"), []byte("# test\n"), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	gitInit := exec.Command("git", "init")
	gitInit.Dir = tempDir
	if output, err := gitInit.CombinedOutput(); err != nil {
		t.Fatalf("git init failed: %v (%s)", err, output)
	}
	t.Setenv("AI_PROVIDER", "openrouter")
	t.Setenv("OPENROUTER_API_KEY", "")
	t.Setenv("OLLAMA_URL", "")

	traceCtx := clitrace.Start("generate")
	result := runGenerateCommand(traceCtx, dashboardConnectionConfig{}, nil)
	if result.ExitCode != types.ExitSuccess && result.ExitCode != types.ExitSystemError {
		t.Fatalf("unexpected exit code %d", result.ExitCode)
	}

	foundGeneratorInit := false
	for _, event := range traceCtx.Events() {
		if event.Type == "cli_helper_exited" && event.Function == "NewDefaultGenerator" && event.Status == "ok" {
			foundGeneratorInit = true
			break
		}
	}
	if !foundGeneratorInit {
		t.Fatal("expected NewDefaultGenerator helper exit trace event for generate")
	}
}

func TestRunPRCommandHelp(t *testing.T) {
	traceCtx := clitrace.Start("pr")
	result := runPRCommand(traceCtx, dashboardConnectionConfig{}, []string{"--help"})
	if result.ExitCode != types.ExitSuccess {
		t.Fatalf("expected exit code %d, got %d", types.ExitSuccess, result.ExitCode)
	}

	foundBranch := false
	for _, event := range traceCtx.Events() {
		if event.Type == "cli_branch_taken" && event.Branch == "help_requested" {
			foundBranch = true
			break
		}
	}
	if !foundBranch {
		t.Fatal("expected help_requested trace event for pr")
	}
}

func TestRunPRCommandRecordsGeneratorInitHelper(t *testing.T) {
	repoDir := setupTempGitRepo(t, "https://github.com/example/baseline.git")
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	defer os.Chdir(oldWD)
	if err := os.Chdir(repoDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	t.Setenv("AI_PROVIDER", "openrouter")
	t.Setenv("OPENROUTER_API_KEY", "")
	t.Setenv("OLLAMA_URL", "")

	traceCtx := clitrace.Start("pr")
	result := runPRCommand(traceCtx, dashboardConnectionConfig{}, nil)
	if result.ExitCode != types.ExitSystemError {
		t.Fatalf("expected exit code %d, got %d", types.ExitSystemError, result.ExitCode)
	}

	foundGeneratorInit := false
	for _, event := range traceCtx.Events() {
		if event.Type == "cli_helper_exited" && event.Function == "NewDefaultGenerator" && event.Status == "ok" {
			foundGeneratorInit = true
			break
		}
	}
	if !foundGeneratorInit {
		t.Fatal("expected NewDefaultGenerator helper exit trace event for pr")
	}
}

func TestRunExplainCommandUnknownPolicy(t *testing.T) {
	traceCtx := clitrace.Start("explain")
	result := runExplainCommand(traceCtx, dashboardConnectionConfig{}, []string{"BAD"})
	if result.ExitCode != types.ExitSystemError {
		t.Fatalf("expected exit code %d, got %d", types.ExitSystemError, result.ExitCode)
	}

	foundError := false
	for _, event := range traceCtx.Events() {
		if event.Type == "cli_error" && event.Function == "explain" {
			foundError = true
			break
		}
	}
	if !foundError {
		t.Fatal("expected cli_error trace event for explain")
	}
}

func TestRunExplainCommandRecordsRemediationHelper(t *testing.T) {
	repoDir := setupTempGitRepo(t, "https://github.com/example/baseline.git")
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	defer os.Chdir(oldWD)
	if err := os.Chdir(repoDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "README.md"), []byte("# test\n"), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	traceCtx := clitrace.Start("explain")
	result := runExplainCommand(traceCtx, dashboardConnectionConfig{}, []string{"A1"})
	if result.ExitCode != types.ExitSuccess {
		t.Fatalf("expected exit code %d, got %d", types.ExitSuccess, result.ExitCode)
	}

	foundRemediation := false
	for _, event := range traceCtx.Events() {
		if event.Type == "cli_helper_exited" && event.Function == "GetRemediationAdvice" && event.Status == "ok" {
			foundRemediation = true
			break
		}
	}
	if !foundRemediation {
		t.Fatal("expected GetRemediationAdvice helper exit trace event for explain")
	}
}

func TestRunSecurityAdviceCommandInvalidArgs(t *testing.T) {
	traceCtx := clitrace.Start("security-advice")
	result := runSecurityAdviceCommand(traceCtx, dashboardConnectionConfig{}, []string{"--bad"})
	if result.ExitCode != types.ExitSystemError {
		t.Fatalf("expected exit code %d, got %d", types.ExitSystemError, result.ExitCode)
	}

	foundError := false
	for _, event := range traceCtx.Events() {
		if event.Type == "cli_error" && event.Function == "parseSecurityAdviceArgs" {
			foundError = true
			break
		}
	}
	if !foundError {
		t.Fatal("expected cli_error trace event for parseSecurityAdviceArgs")
	}
}

func TestRunSecurityAdviceCommandRecordsGeneratorInitHelper(t *testing.T) {
	repoDir := setupTempGitRepo(t, "https://github.com/example/baseline.git")
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	defer os.Chdir(oldWD)
	if err := os.Chdir(repoDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	t.Setenv("AI_PROVIDER", "openrouter")
	t.Setenv("OPENROUTER_API_KEY", "")
	t.Setenv("OLLAMA_URL", "")

	traceCtx := clitrace.Start("security-advice")
	result := runSecurityAdviceCommand(traceCtx, dashboardConnectionConfig{}, nil)
	if result.ExitCode != types.ExitSystemError {
		t.Fatalf("expected exit code %d, got %d", types.ExitSystemError, result.ExitCode)
	}

	foundGeneratorInit := false
	for _, event := range traceCtx.Events() {
		if event.Type == "cli_helper_exited" && event.Function == "NewDefaultGenerator" && event.Status == "ok" {
			foundGeneratorInit = true
			break
		}
	}
	if !foundGeneratorInit {
		t.Fatal("expected NewDefaultGenerator helper exit trace event for security-advice")
	}
}

func TestRunAPICommandHelp(t *testing.T) {
	traceCtx := clitrace.Start("api")
	result := runAPICommand(traceCtx, "api", []string{"help"})
	if result.ExitCode != types.ExitSuccess {
		t.Fatalf("expected exit code %d, got %d", types.ExitSuccess, result.ExitCode)
	}

	foundBranch := false
	for _, event := range traceCtx.Events() {
		if event.Type == "cli_branch_taken" && event.Branch == "help_requested" {
			foundBranch = true
			break
		}
	}
	if !foundBranch {
		t.Fatal("expected help_requested trace event for api")
	}
}

func TestRunAPICommandKeygen(t *testing.T) {
	traceCtx := clitrace.Start("api keygen")
	result := runAPICommand(traceCtx, "api keygen", []string{"keygen"})
	if result.ExitCode != types.ExitSuccess {
		t.Fatalf("expected exit code %d, got %d", types.ExitSuccess, result.ExitCode)
	}

	foundHelper := false
	for _, event := range traceCtx.Events() {
		if event.Type == "cli_helper_exited" && event.Function == "generateAPIKey" && event.Status == "ok" {
			foundHelper = true
			break
		}
	}
	if !foundHelper {
		t.Fatal("expected generateAPIKey helper trace event for api keygen")
	}
}

func TestRunEnforceCommandRecordsErrorTraceOutsideGitRepo(t *testing.T) {
	tempDir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	defer os.Chdir(oldWD)
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}

	traceCtx := clitrace.Start("enforce")
	result := runEnforceCommand(traceCtx, dashboardConnectionConfig{})
	if result.ExitCode != types.ExitSystemError {
		t.Fatalf("expected exit code %d, got %d", types.ExitSystemError, result.ExitCode)
	}
}

func TestRunInitCommandRequiresGitRepo(t *testing.T) {
	tempDir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	defer os.Chdir(oldWD)
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}

	traceCtx := clitrace.Start("init")
	result := runInitCommand(traceCtx, nil)
	if result.ExitCode != types.ExitSystemError {
		t.Fatalf("expected exit code %d, got %d", types.ExitSystemError, result.ExitCode)
	}
}

func TestRunInitCommandHelpDoesNotTouchRepoConfig(t *testing.T) {
	repoDir := setupTempGitRepo(t, "https://github.com/example/baseline.git")
	configPath := filepath.Join(repoDir, ".baseline", "config.yaml")
	t.Setenv("BASELINE_CONFIG_PATH", configPath)

	cfg := baselineLocalConfig{
		PolicySet:       "custom:policy",
		EnforcementMode: "block",
		Dashboard: baselineDashboardConfig{
			Upload: dashboardUploadConfig{
				Prompted:   true,
				Enabled:    true,
				APIBaseURL: "http://127.0.0.1:8080",
				ProjectID:  "baseline_repo",
			},
		},
	}
	if err := saveBaselineLocalConfig(cfg); err != nil {
		t.Fatalf("saveBaselineLocalConfig: %v", err)
	}

	traceCtx := clitrace.Start("init")
	result := runInitCommand(traceCtx, []string{"--help"})
	if result.ExitCode != types.ExitSuccess {
		t.Fatalf("expected help exit code %d, got %d", types.ExitSuccess, result.ExitCode)
	}

	savedConfig, err := loadBaselineLocalConfig()
	if err != nil {
		t.Fatalf("loadBaselineLocalConfig: %v", err)
	}
	if savedConfig != cfg {
		t.Fatalf("expected config to remain unchanged after init help, got %+v", savedConfig)
	}
}

func TestRunInitCommandPreservesDashboardUploadConfig(t *testing.T) {
	repoDir := setupTempGitRepo(t, "https://github.com/example/baseline.git")
	configPath := filepath.Join(repoDir, ".baseline", "config.yaml")
	t.Setenv("BASELINE_CONFIG_PATH", configPath)

	cfg := baselineLocalConfig{
		Dashboard: baselineDashboardConfig{
			Upload: dashboardUploadConfig{
				Prompted:   true,
				Enabled:    true,
				APIBaseURL: "http://127.0.0.1:8080",
				ProjectID:  "baseline_repo",
			},
		},
	}
	if err := saveBaselineLocalConfig(cfg); err != nil {
		t.Fatalf("saveBaselineLocalConfig: %v", err)
	}

	traceCtx := clitrace.Start("init")
	result := runInitCommand(traceCtx, nil)
	if result.ExitCode != types.ExitSuccess {
		t.Fatalf("expected init success, got %d", result.ExitCode)
	}

	savedConfig, err := loadBaselineLocalConfig()
	if err != nil {
		t.Fatalf("loadBaselineLocalConfig: %v", err)
	}
	if savedConfig.PolicySet != "baseline:prod" {
		t.Fatalf("expected policy_set baseline:prod, got %q", savedConfig.PolicySet)
	}
	if savedConfig.EnforcementMode != "audit" {
		t.Fatalf("expected enforcement_mode audit, got %q", savedConfig.EnforcementMode)
	}
	if savedConfig.Dashboard.Upload.ProjectID != "baseline_repo" || savedConfig.Dashboard.Upload.APIBaseURL != "http://127.0.0.1:8080" || !savedConfig.Dashboard.Upload.Enabled {
		t.Fatalf("expected dashboard upload config to be preserved, got %+v", savedConfig.Dashboard.Upload)
	}
}
