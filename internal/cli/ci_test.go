package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	clitrace "github.com/baseline/baseline/internal/cli/trace"
	"github.com/baseline/baseline/internal/types"
)

func TestParseCISetupArgs(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantProvider string
		wantMode     string
		wantForce    bool
		wantErr      bool
	}{
		{
			name:         "defaults",
			args:         []string{},
			wantProvider: "github",
			wantMode:     "enforce",
		},
		{
			name:         "check mode with force",
			args:         []string{"--mode", "check", "--force"},
			wantProvider: "github",
			wantMode:     "check",
			wantForce:    true,
		},
		{
			name:         "gitlab alias",
			args:         []string{"--provider", "gitlab-ci"},
			wantProvider: "gitlab",
			wantMode:     "enforce",
		},
		{
			name:         "azure alias",
			args:         []string{"--provider", "azure-devops"},
			wantProvider: "azure",
			wantMode:     "enforce",
		},
		{
			name:    "invalid mode",
			args:    []string{"--mode", "deploy"},
			wantErr: true,
		},
		{
			name:    "missing provider value",
			args:    []string{"--provider"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := parseCISetupArgs(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for args %v", tt.args)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCISetupArgs returned error: %v", err)
			}
			if opts.Provider != tt.wantProvider {
				t.Fatalf("expected provider %q, got %q", tt.wantProvider, opts.Provider)
			}
			if opts.Mode != tt.wantMode {
				t.Fatalf("expected mode %q, got %q", tt.wantMode, opts.Mode)
			}
			if opts.Force != tt.wantForce {
				t.Fatalf("expected force %v, got %v", tt.wantForce, opts.Force)
			}
		})
	}
}

func TestRunCISetupCommandCreatesGitHubWorkflow(t *testing.T) {
	repoDir := initTempGitRepo(t)
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer os.Chdir(oldWd)
	if err := os.Chdir(repoDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	result := runCISetupCommand(clitrace.Start("ci"), nil)
	if result.ExitCode != types.ExitSuccess {
		t.Fatalf("expected success, got %d", result.ExitCode)
	}

	workflowPath := filepath.Join(repoDir, ".github", "workflows", "baseline.yml")
	content, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	workflow := string(content)
	if !strings.Contains(workflow, "uses: actions/checkout@v4") {
		t.Fatalf("expected checkout step in workflow, got:\n%s", workflow)
	}
	if !strings.Contains(workflow, "go install github.com/baseline/baseline/cmd/baseline@latest") {
		t.Fatalf("expected generic install step in workflow, got:\n%s", workflow)
	}
	if !strings.Contains(workflow, "run: baseline enforce") {
		t.Fatalf("expected generic enforce command in workflow, got:\n%s", workflow)
	}
}

func TestRunCISetupCommandCreatesGitLabWorkflow(t *testing.T) {
	repoDir := initTempGitRepo(t)
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer os.Chdir(oldWd)
	if err := os.Chdir(repoDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	result := runCISetupCommand(clitrace.Start("ci"), []string{"--provider", "gitlab"})
	if result.ExitCode != types.ExitSuccess {
		t.Fatalf("expected success, got %d", result.ExitCode)
	}

	content, err := os.ReadFile(filepath.Join(repoDir, ".gitlab-ci.yml"))
	if err != nil {
		t.Fatalf("read gitlab workflow: %v", err)
	}
	workflow := string(content)
	if !strings.Contains(workflow, "image: golang:1.26") {
		t.Fatalf("expected golang image in workflow, got:\n%s", workflow)
	}
	if !strings.Contains(workflow, "go install github.com/baseline/baseline/cmd/baseline@latest") {
		t.Fatalf("expected generic install step in workflow, got:\n%s", workflow)
	}
	if !strings.Contains(workflow, "- baseline enforce") {
		t.Fatalf("expected enforce command in workflow, got:\n%s", workflow)
	}
}

func TestRunCISetupCommandCreatesAzureWorkflow(t *testing.T) {
	repoDir := initTempGitRepo(t)
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer os.Chdir(oldWd)
	if err := os.Chdir(repoDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	result := runCISetupCommand(clitrace.Start("ci"), []string{"--provider", "azure", "--mode", "check"})
	if result.ExitCode != types.ExitSuccess {
		t.Fatalf("expected success, got %d", result.ExitCode)
	}

	content, err := os.ReadFile(filepath.Join(repoDir, "azure-pipelines.yml"))
	if err != nil {
		t.Fatalf("read azure workflow: %v", err)
	}
	workflow := string(content)
	if !strings.Contains(workflow, "task: GoTool@0") {
		t.Fatalf("expected GoTool task in workflow, got:\n%s", workflow)
	}
	if !strings.Contains(workflow, "go install github.com/baseline/baseline/cmd/baseline@latest") {
		t.Fatalf("expected generic install step in workflow, got:\n%s", workflow)
	}
	if !strings.Contains(workflow, "script: baseline check") {
		t.Fatalf("expected check command in workflow, got:\n%s", workflow)
	}
}

func TestRunCISetupCommandBuildsLocalCLIForBaselineSourceRepo(t *testing.T) {
	repoDir := initTempBaselineSourceRepo(t)
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer os.Chdir(oldWd)
	if err := os.Chdir(repoDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	result := runCISetupCommand(clitrace.Start("ci"), []string{"--provider", "github"})
	if result.ExitCode != types.ExitSuccess {
		t.Fatalf("expected success, got %d", result.ExitCode)
	}

	content, err := os.ReadFile(filepath.Join(repoDir, ".github", "workflows", "baseline.yml"))
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	workflow := string(content)
	if !strings.Contains(workflow, "go-version-file: go.mod") {
		t.Fatalf("expected go.mod-based setup in workflow, got:\n%s", workflow)
	}
	if !strings.Contains(workflow, "go build -o baseline ./cmd/baseline") {
		t.Fatalf("expected local build step in workflow, got:\n%s", workflow)
	}
	if !strings.Contains(workflow, "run: ./baseline enforce") {
		t.Fatalf("expected local run command in workflow, got:\n%s", workflow)
	}
}

func TestRunCISetupCommandRequiresForceToOverwrite(t *testing.T) {
	repoDir := initTempGitRepo(t)
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer os.Chdir(oldWd)
	if err := os.Chdir(repoDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	workflowPath := filepath.Join(".github", "workflows", "baseline.yml")
	if err := os.MkdirAll(filepath.Dir(workflowPath), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(workflowPath, []byte("existing"), 0644); err != nil {
		t.Fatalf("write existing workflow: %v", err)
	}

	result := runCISetupCommand(clitrace.Start("ci"), nil)
	if result.ExitCode != types.ExitSystemError {
		t.Fatalf("expected system error when workflow exists, got %d", result.ExitCode)
	}

	result = runCISetupCommand(clitrace.Start("ci"), []string{"--force", "--mode", "check"})
	if result.ExitCode != types.ExitSuccess {
		t.Fatalf("expected success with force, got %d", result.ExitCode)
	}
	content, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	if !strings.Contains(string(content), "run: baseline check") {
		t.Fatalf("expected check command after overwrite, got:\n%s", string(content))
	}
}

func initTempGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cmd := exec.Command("git", "init")
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init failed: %v\n%s", err, string(output))
	}
	return dir
}

func initTempBaselineSourceRepo(t *testing.T) string {
	t.Helper()
	dir := initTempGitRepo(t)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module github.com/baseline/baseline\n\ngo 1.26.0\n"), 0644); err != nil {
		t.Fatalf("write go.mod failed: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "cmd", "baseline"), 0755); err != nil {
		t.Fatalf("mkdir cmd/baseline failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cmd", "baseline", "main.go"), []byte("package main\nfunc main() {}\n"), 0644); err != nil {
		t.Fatalf("write main.go failed: %v", err)
	}
	return dir
}
