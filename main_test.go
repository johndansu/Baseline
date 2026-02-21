package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCLIHelpOutput(t *testing.T) {
	cmd := exec.Command("go", "run", "./cmd/baseline", "--help")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected help command to succeed, got error: %v\noutput: %s", err, string(output))
	}

	help := string(output)
	requiredSections := []string{
		"baseline - Production Policy & Enforcement Engine",
		"Usage:",
		"Commands:",
		"Exit Codes:",
	}

	for _, section := range requiredSections {
		if !strings.Contains(help, section) {
			t.Fatalf("help output missing section %q\noutput: %s", section, help)
		}
	}
}

func TestCLIContract_NoArgsReturnsSystemError(t *testing.T) {
	bin := buildCLIBinary(t)
	workDir := t.TempDir()

	output, exitCode := runCLI(t, bin, workDir, nil)
	if exitCode != 50 {
		t.Fatalf("expected exit code 50 for no-arg usage failure, got %d. Output: %s", exitCode, output)
	}
	if !strings.Contains(output, "Usage:") {
		t.Fatalf("expected usage output for no-arg invocation. Output: %s", output)
	}
}

func TestCLIContract_UnknownCommandReturnsSystemError(t *testing.T) {
	bin := buildCLIBinary(t)
	workDir := t.TempDir()

	output, exitCode := runCLI(t, bin, workDir, nil, "wat")
	if exitCode != 50 {
		t.Fatalf("expected exit code 50 for unknown command, got %d. Output: %s", exitCode, output)
	}
	if !strings.Contains(output, "Unknown command: wat") {
		t.Fatalf("expected unknown command output, got: %s", output)
	}
}

func TestCLIContract_ReportFormatsAndInvalidFlag(t *testing.T) {
	bin := buildCLIBinary(t)
	repoDir := createTempGitRepo(t)

	jsonOut, jsonExit := runCLI(t, bin, repoDir, nil, "report", "--json")
	if jsonExit != 0 {
		t.Fatalf("expected report --json exit 0, got %d. Output: %s", jsonExit, jsonOut)
	}
	if !strings.Contains(jsonOut, "\"files_scanned\"") {
		t.Fatalf("expected JSON output from report --json. Output: %s", jsonOut)
	}

	sarifOut, sarifExit := runCLI(t, bin, repoDir, nil, "report", "--sarif")
	if sarifExit != 0 {
		t.Fatalf("expected report --sarif exit 0, got %d. Output: %s", sarifExit, sarifOut)
	}
	if !strings.Contains(sarifOut, "\"version\": \"2.1.0\"") {
		t.Fatalf("expected SARIF output from report --sarif. Output: %s", sarifOut)
	}

	invalidOut, invalidExit := runCLI(t, bin, repoDir, nil, "report", "--wat")
	if invalidExit != 50 {
		t.Fatalf("expected report invalid flag exit 50, got %d. Output: %s", invalidExit, invalidOut)
	}
	if !strings.Contains(invalidOut, "unknown flag --wat") {
		t.Fatalf("expected unknown flag error output, got: %s", invalidOut)
	}
}

func TestCLIContract_CheckAndScanViolationExitCode(t *testing.T) {
	bin := buildCLIBinary(t)
	repoDir := createTempGitRepo(t)

	checkOut, checkExit := runCLI(t, bin, repoDir, nil, "check")
	if checkExit != 20 {
		t.Fatalf("expected check exit 20 for blocking violations, got %d. Output: %s", checkExit, checkOut)
	}

	scanOut, scanExit := runCLI(t, bin, repoDir, nil, "scan")
	if scanExit != 20 {
		t.Fatalf("expected scan exit 20 for blocking violations, got %d. Output: %s", scanExit, scanOut)
	}
}

func buildCLIBinary(t *testing.T) string {
	t.Helper()

	repoRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	binPath := filepath.Join(t.TempDir(), "baseline-contract")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}

	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/baseline")
	cmd.Dir = repoRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build baseline CLI: %v\n%s", err, string(output))
	}

	return binPath
}

func runCLI(t *testing.T, binPath, dir string, extraEnv []string, args ...string) (string, int) {
	t.Helper()

	cmd := exec.Command(binPath, args...)
	cmd.Dir = dir
	cmd.Env = sanitizedEnv(extraEnv...)

	output, err := cmd.CombinedOutput()
	return string(output), commandExitCode(err)
}

func commandExitCode(err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return -1
}

func sanitizedEnv(extra ...string) []string {
	filtered := make([]string, 0, len(os.Environ())+len(extra))
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "BASELINE_API_KEY=") ||
			strings.HasPrefix(kv, "BASELINE_API_KEYS=") ||
			strings.HasPrefix(kv, "BASELINE_API_ENV_FILE=") {
			continue
		}
		filtered = append(filtered, kv)
	}
	filtered = append(filtered, "BASELINE_API_KEY=", "BASELINE_API_KEYS=", "BASELINE_API_ENV_FILE=")
	filtered = append(filtered, extra...)
	return filtered
}

func createTempGitRepo(t *testing.T) string {
	t.Helper()

	repoDir := t.TempDir()
	initCmd := exec.Command("git", "init")
	initCmd.Dir = repoDir
	if output, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to initialize temp git repo: %v\n%s", err, string(output))
	}

	return repoDir
}
