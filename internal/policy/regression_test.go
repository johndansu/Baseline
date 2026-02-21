package policy

import (
	"os"
	"testing"
)

func TestCheckPlaintextSecretsIgnoresPlaceholderHelpText(t *testing.T) {
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)

	tempDir, err := os.MkdirTemp("", "baseline-policy-regression-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}

	content := `package main

import "fmt"

func usage() {
	fmt.Println("BASELINE_API_ENROLLMENT_TOKENS=<token:role,token:role>")
}`
	if err := os.WriteFile("help_text.go", []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	violation := CheckPlaintextSecrets()
	if violation != nil {
		t.Fatalf("expected no secret violation for placeholder help text, got: %+v", *violation)
	}
}

func TestCheckPlaintextSecretsStillDetectsRealAssignment(t *testing.T) {
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)

	tempDir, err := os.MkdirTemp("", "baseline-policy-regression-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}

	content := `package main

var password = "super-secret-value"`
	if err := os.WriteFile("secrets.go", []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	violation := CheckPlaintextSecrets()
	if violation == nil {
		t.Fatal("expected secret violation for real assignment, got nil")
	}
}

func TestCheckSecurityScanningIgnoresUnsafePointerLiteral(t *testing.T) {
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)

	tempDir, err := os.MkdirTemp("", "baseline-policy-regression-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}

	content := `package main

import "strings"

func detector(line string) bool {
	return strings.Contains(line, "unsafe.Pointer")
}`
	if err := os.WriteFile("detector.go", []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	violation := CheckSecurityScanning()
	if violation != nil {
		t.Fatalf("expected no security violation for unsafe.Pointer literal, got: %+v", *violation)
	}
}

func TestCheckSecurityScanningDetectsRealUnsafePointer(t *testing.T) {
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)

	tempDir, err := os.MkdirTemp("", "baseline-policy-regression-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}

	content := `package main

import "unsafe"

func main() {
	var x int
	_ = unsafe.Pointer(&x)
}`
	if err := os.WriteFile("unsafe_usage.go", []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	violation := CheckSecurityScanning()
	if violation == nil {
		t.Fatal("expected security violation for real unsafe.Pointer usage, got nil")
	}
}

func TestCheckSecurityScanningIgnoresNonSQLUpdateStrings(t *testing.T) {
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)

	tempDir, err := os.MkdirTemp("", "baseline-policy-regression-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}

	content := `package main

func message() string {
	body := "Review notes:\n"
	body += "- Update documentation as needed\n"
	return body
}`
	if err := os.WriteFile("nonsql.go", []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	violation := CheckSecurityScanning()
	if violation != nil {
		t.Fatalf("expected no SQL-injection violation for natural language update string, got: %+v", *violation)
	}
}

func TestVerifyProtectedBranchRequirementFromDocumentationProxyFails(t *testing.T) {
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)

	tempDir, err := os.MkdirTemp("", "baseline-policy-regression-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}

	doc := `# Branch protection
- Branch: main
- Require pull request reviews before merging
- Restrict pushes`
	if err := os.WriteFile("branch-protection-setup.md", []byte(doc), 0644); err != nil {
		t.Fatalf("failed to write branch protection doc: %v", err)
	}

	ok, err := verifyProtectedBranchRequirement("main")
	if err != nil {
		t.Fatalf("verifyProtectedBranchRequirement returned error: %v", err)
	}
	if ok {
		t.Fatal("expected docs-only branch protection evidence to fail verification")
	}
}

func TestParseGitHubWorkflowRequirements(t *testing.T) {
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
	hasPR, hasTests, err := parseGitHubWorkflowRequirements([]byte(workflow))
	if err != nil {
		t.Fatalf("parseGitHubWorkflowRequirements returned error: %v", err)
	}
	if !hasPR {
		t.Fatal("expected PR trigger detection")
	}
	if !hasTests {
		t.Fatal("expected CI test execution detection")
	}
}
