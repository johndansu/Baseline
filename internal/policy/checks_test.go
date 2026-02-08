package policy

import (
	"os"
	"testing"

	"github.com/baseline/baseline/internal/types"
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

	// Create GitHub Actions workflow
	os.MkdirAll(".github/workflows", 0755)
	os.WriteFile(".github/workflows/ci.yml", []byte("name: CI"), 0644)

	// Test: Should pass with CI file
	violation = CheckCIPipeline()
	if violation != nil {
		t.Errorf("Expected no violation with CI file, got: %v", violation)
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
