package policy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baseline/baseline/internal/types"
	"gopkg.in/yaml.v3"
)

func TestContainsAny(t *testing.T) {
	testCases := []struct {
		name     string
		str      string
		patterns []string
		expected bool
	}{
		{"match first", "hello world", []string{"hello", "foo"}, true},
		{"match second", "hello world", []string{"foo", "world"}, true},
		{"no match", "hello world", []string{"foo", "bar"}, false},
		{"empty patterns", "hello", []string{}, false},
		{"empty string", "", []string{"hello"}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := containsAny(tc.str, tc.patterns)
			if result != tc.expected {
				t.Errorf("containsAny(%q, %v) = %v, expected %v",
					tc.str, tc.patterns, result, tc.expected)
			}
		})
	}
}

func TestCheckDocumentation(t *testing.T) {
	// Save current directory
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)

	// Create temp directory for test
	tempDir, err := os.MkdirTemp("", "baseline-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	os.Chdir(tempDir)

	// Test: No README
	violation := CheckDocumentation()
	if violation == nil {
		t.Error("Expected violation when README.md is missing")
	}
	if violation != nil && violation.PolicyID != types.PolicyDocumentation {
		t.Errorf("Expected PolicyID %s, got %s", types.PolicyDocumentation, violation.PolicyID)
	}

	// Create minimal README
	os.WriteFile("README.md", []byte("# Test\n## Section"), 0644)

	// Test: No LICENSE
	violation = CheckDocumentation()
	if violation == nil {
		t.Error("Expected violation when LICENSE is missing")
	}

	// Create LICENSE
	os.WriteFile("LICENSE", []byte("MIT License"), 0644)

	// Test: Should pass now
	violation = CheckDocumentation()
	if violation != nil {
		t.Errorf("Expected no violation, got: %v", violation)
	}
}

func TestCheckCIPipeline(t *testing.T) {
	// Save current directory
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)

	// Create temp directory for test
	tempDir, err := os.MkdirTemp("", "baseline-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	os.Chdir(tempDir)

	// Test: No CI files
	violation := CheckCIPipeline()
	if violation == nil {
		t.Error("Expected violation when no CI files exist")
	}
	if violation != nil && violation.PolicyID != types.PolicyCIPipeline {
		t.Errorf("Expected PolicyID %s, got %s", types.PolicyCIPipeline, violation.PolicyID)
	}

	// Create GitHub Actions workflow with PR trigger and test execution
	os.MkdirAll(".github/workflows", 0755)
	workflow := `name: CI
on:
  pull_request:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: go test ./...
`
	os.WriteFile(".github/workflows/ci.yml", []byte(workflow), 0644)

	// Test: Should pass with CI file
	violation = CheckCIPipeline()
	if violation != nil {
		t.Errorf("Expected no violation with CI file, got: %v", violation)
	}
}

func TestCheckCIPipelineRequiresPullRequestAndTests(t *testing.T) {
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)

	tempDir, err := os.MkdirTemp("", "baseline-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	os.Chdir(tempDir)
	os.MkdirAll(".github/workflows", 0755)

	missingPR := `name: CI
on:
  push:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: go test ./...
`
	os.WriteFile(".github/workflows/ci.yml", []byte(missingPR), 0644)

	violation := CheckCIPipeline()
	if violation == nil {
		t.Fatal("Expected violation when pull_request trigger is missing")
	}

	withPRNoTests := `name: CI
on:
  pull_request:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: go build ./...
`
	os.WriteFile(".github/workflows/ci.yml", []byte(withPRNoTests), 0644)
	violation = CheckCIPipeline()
	if violation == nil {
		t.Fatal("Expected violation when CI tests are missing")
	}
}

func TestCheckTestSuite(t *testing.T) {
	// Save current directory
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)

	// Create temp directory for test
	tempDir, err := os.MkdirTemp("", "baseline-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	os.Chdir(tempDir)

	// Test: No test files
	violation := CheckTestSuite()
	if violation == nil {
		t.Error("Expected violation when no test files exist")
	}

	// Create a test file
	os.WriteFile("main_test.go", []byte("package main"), 0644)

	// Test: Should pass with test file
	violation = CheckTestSuite()
	if violation != nil {
		t.Errorf("Expected no violation with test file, got: %v", violation)
	}
}

func TestCheckDependencyManagement(t *testing.T) {
	// Save current directory
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)

	// Create temp directory for test
	tempDir, err := os.MkdirTemp("", "baseline-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	os.Chdir(tempDir)

	// Test: No dependency files
	violation := CheckDependencyManagement()
	if violation == nil {
		t.Error("Expected violation when no dependency files exist")
	}

	// Create go.mod
	os.WriteFile("go.mod", []byte("module test\n\ngo 1.21"), 0644)

	// Test: Should pass with go.mod
	violation = CheckDependencyManagement()
	if violation != nil {
		t.Errorf("Expected no violation with go.mod, got: %v", violation)
	}
}

func TestCheckRollbackPlan(t *testing.T) {
	// Save current directory
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)

	// Create temp directory for test
	tempDir, err := os.MkdirTemp("", "baseline-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	os.Chdir(tempDir)

	// Test: No rollback docs
	violation := CheckRollbackPlan()
	if violation == nil {
		t.Error("Expected violation when no rollback docs exist")
	}

	// Create ROLLBACK.md
	os.WriteFile("ROLLBACK.md", []byte("# Rollback Plan"), 0644)

	// Test: Should pass with ROLLBACK.md
	violation = CheckRollbackPlan()
	if violation != nil {
		t.Errorf("Expected no violation with ROLLBACK.md, got: %v", violation)
	}
}

func TestCheckEnvironmentVariables(t *testing.T) {
	// Save current directory
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)

	// Create temp directory for test
	tempDir, err := os.MkdirTemp("", "baseline-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	os.Chdir(tempDir)

	// Test: No env files
	violation := CheckEnvironmentVariables()
	if violation == nil {
		t.Error("Expected violation when no env files exist")
	}

	// Create .env.example
	os.WriteFile(".env.example", []byte("DATABASE_URL=changeme"), 0644)

	// Test: Should pass with .env.example
	violation = CheckEnvironmentVariables()
	if violation != nil {
		t.Errorf("Expected no violation with .env.example, got: %v", violation)
	}
}

func TestRunAllChecks(t *testing.T) {
	// This is an integration test - just verify it doesn't panic
	// In a proper test environment, we'd mock the file system
	violations := RunAllChecks()

	// Verify we get back a slice (even if empty)
	if violations == nil {
		// This is actually fine - nil slice is valid
		violations = []types.PolicyViolation{}
	}

	// Just verify the function completes without panic
	t.Logf("RunAllChecks returned %d violations", len(violations))
}

func TestCheckCIPipelineRequiresTestsOnPullRequestWorkflow(t *testing.T) {
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)

	tempDir, err := os.MkdirTemp("", "baseline-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	os.Chdir(tempDir)
	os.MkdirAll(".github/workflows", 0755)

	prNoTests := `name: PR validation
on:
  pull_request:
    branches: [main]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: go vet ./...
`
	pushWithTests := `name: Push tests
on:
  push:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: go test ./...
`

	os.WriteFile(".github/workflows/pr.yml", []byte(prNoTests), 0644)
	os.WriteFile(".github/workflows/push.yml", []byte(pushWithTests), 0644)

	violation := CheckCIPipeline()
	if violation == nil {
		t.Fatal("Expected violation when tests do not run on pull_request workflows")
	}
	if violation.PolicyID != types.PolicyCIPipeline {
		t.Fatalf("Expected policy %s, got %s", types.PolicyCIPipeline, violation.PolicyID)
	}
}

func TestCheckCIPipelineAllowsArrayTriggerWithTests(t *testing.T) {
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)

	tempDir, err := os.MkdirTemp("", "baseline-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	os.Chdir(tempDir)
	os.MkdirAll(".github/workflows", 0755)

	workflow := `name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: go test ./...
`
	os.WriteFile(".github/workflows/ci.yml", []byte(workflow), 0644)

	violation := CheckCIPipeline()
	if violation != nil {
		t.Fatalf("Expected no violation, got %v", violation)
	}
}

func TestVerifyProtectedBranchRequirementUsesGitHubAPIWhenAvailable(t *testing.T) {
	origRemoteReader := gitRemoteOriginReader
	origClientFactory := httpClientFactory
	origAPIBase := githubAPIBaseURL
	defer func() {
		gitRemoteOriginReader = origRemoteReader
		httpClientFactory = origClientFactory
		githubAPIBaseURL = origAPIBase
	}()

	server := newTestHTTPServer(t, `{"required_pull_request_reviews":{"required_approving_review_count":1},"enforce_admins":{"enabled":true},"restrictions":null}`, 200)
	defer server.Close()

	gitRemoteOriginReader = func() (string, error) {
		return "https://github.com/example/repo.git", nil
	}
	httpClientFactory = server.Client
	githubAPIBaseURL = server.URL
	t.Setenv("GITHUB_TOKEN", "test-token")
	t.Setenv("GH_TOKEN", "")

	protected, err := verifyProtectedBranchRequirement("main")
	if err != nil {
		t.Fatalf("verifyProtectedBranchRequirement returned error: %v", err)
	}
	if !protected {
		t.Fatal("Expected branch to be protected from GitHub API response")
	}
}

func TestVerifyProtectedBranchRequirementConfigFallback(t *testing.T) {
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)

	origRemoteReader := gitRemoteOriginReader
	defer func() { gitRemoteOriginReader = origRemoteReader }()
	gitRemoteOriginReader = func() (string, error) {
		return "", fmt.Errorf("no remote")
	}

	tempDir, err := os.MkdirTemp("", "baseline-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	os.Chdir(tempDir)
	os.MkdirAll(".github", 0755)
	settings := `branches:
  - name: main
    protection:
      required_pull_request_reviews:
        required_approving_review_count: 1
      enforce_admins: true
`
	os.WriteFile(".github/settings.yml", []byte(settings), 0644)

	protected, err := verifyProtectedBranchRequirement("main")
	if err != nil {
		t.Fatalf("verifyProtectedBranchRequirement returned error: %v", err)
	}
	if !protected {
		t.Fatal("Expected config-based branch protection to pass")
	}
}

func TestVerifyProtectedBranchRequirementDoesNotAcceptDocsProxy(t *testing.T) {
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)

	origRemoteReader := gitRemoteOriginReader
	defer func() { gitRemoteOriginReader = origRemoteReader }()
	gitRemoteOriginReader = func() (string, error) {
		return "", fmt.Errorf("no remote")
	}

	tempDir, err := os.MkdirTemp("", "baseline-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	os.Chdir(tempDir)
	os.WriteFile("branch-protection-setup.md", []byte("protect main with pull request and restrict pushes"), 0644)

	protected, err := verifyProtectedBranchRequirement("main")
	if err != nil {
		t.Fatalf("verifyProtectedBranchRequirement returned error: %v", err)
	}
	if protected {
		t.Fatal("Expected docs-only branch protection proxy to fail")
	}
}

func newTestHTTPServer(t *testing.T, body string, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestPolicyManifestSeverityAlignment(t *testing.T) {
	content, err := os.ReadFile(filepath.Clean(filepath.Join("..", "..", "policy-manifest.yaml")))
	if err != nil {
		t.Fatalf("Failed to read policy-manifest.yaml: %v", err)
	}

	var manifest struct {
		Policies []struct {
			ID       string `yaml:"id"`
			Severity string `yaml:"severity"`
		} `yaml:"policies"`
	}
	if err := yaml.Unmarshal(content, &manifest); err != nil {
		t.Fatalf("Failed to parse policy-manifest.yaml: %v", err)
	}

	for _, policy := range manifest.Policies {
		if strings.TrimSpace(policy.ID) == "" {
			t.Fatal("policy-manifest.yaml contains policy entry with empty id")
		}
		if strings.ToLower(strings.TrimSpace(policy.Severity)) != types.SeverityBlock {
			t.Fatalf("policy %s severity mismatch: expected %s got %s", policy.ID, types.SeverityBlock, policy.Severity)
		}
	}
}
