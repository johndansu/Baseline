package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/baseline/baseline/internal/types"
)

func TestRunComprehensiveScan(t *testing.T) {
	// Test in current directory (should be a git repo)
	results := RunComprehensiveScan()

	// Verify results structure
	if results.FilesScanned < 0 {
		t.Error("FilesScanned should not be negative")
	}

	if results.SecurityIssues < 0 {
		t.Error("SecurityIssues should not be negative")
	}

	// Should have some violations array (even if empty)
	if results.Violations == nil {
		t.Error("Violations should not be nil")
	}
}

func TestRunComprehensiveScanWithGoFiles(t *testing.T) {
	// Create temporary directory with Go files
	tempDir := t.TempDir()
	oldWd, _ := os.Getwd()
	defer os.Chdir(oldWd)

	os.Chdir(tempDir)

	// Create test Go files
	testFiles := []string{"main.go", "utils.go", "test.go"}
	for _, file := range testFiles {
		if err := os.WriteFile(file, []byte("package main"), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", file, err)
		}
	}

	results := RunComprehensiveScan()

	// Should count the Go files
	expectedGoFiles := len(testFiles)
	if results.FilesScanned < expectedGoFiles {
		t.Errorf("Expected at least %d files scanned, got %d", expectedGoFiles, results.FilesScanned)
	}
}

func TestRunComprehensiveScanWithConfigFiles(t *testing.T) {
	// Create temporary directory with config files
	tempDir := t.TempDir()
	oldWd, _ := os.Getwd()
	defer os.Chdir(oldWd)

	os.Chdir(tempDir)

	// Create test config files
	configFiles := []string{".env", "config.yml", "secrets.json"}
	for _, file := range configFiles {
		if err := os.WriteFile(file, []byte("test config"), 0644); err != nil {
			t.Fatalf("Failed to create config file %s: %v", file, err)
		}
	}

	results := RunComprehensiveScan()

	// Should count the config files
	expectedConfigFiles := len(configFiles)
	if results.FilesScanned < expectedConfigFiles {
		t.Errorf("Expected at least %d files scanned, got %d", expectedConfigFiles, results.FilesScanned)
	}
}

func TestRunComprehensiveScanSecurityIssues(t *testing.T) {
	// Test security issue counting
	results := RunComprehensiveScan()

	// Count security-related violations manually
	expectedSecurityIssues := 0
	for _, violation := range results.Violations {
		if len(violation.PolicyID) > 0 {
			if violation.PolicyID[0] == 'D' || 
			   violation.PolicyID[0] == 'G' ||
			   violation.PolicyID == types.PolicySystemError {
				expectedSecurityIssues++
			}
		}
	}

	if results.SecurityIssues != expectedSecurityIssues {
		t.Errorf("Expected %d security issues, got %d", expectedSecurityIssues, results.SecurityIssues)
	}
}

func TestFileScanning(t *testing.T) {
	// Test file scanning logic
	tempDir := t.TempDir()
	oldWd, _ := os.Getwd()
	defer os.Chdir(oldWd)

	os.Chdir(tempDir)

	// Test with no files
	results := RunComprehensiveScan()
	if results.FilesScanned < 0 {
		t.Error("FilesScanned should not be negative with no files")
	}

	// Create a mix of files
	files := map[string]string{
		"main.go":     "package main",
		"utils.go":    "package main",
		".env":        "API_KEY=test",
		"config.yml":  "app: test",
		"README.md":   "# Test",
		"test.txt":    "test content",
	}

	for filename, content := range files {
		if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create file %s: %v", filename, err)
		}
	}

	results = RunComprehensiveScan()

	// Should count Go files and config files
	expectedCount := 0
	for filename := range files {
		if filepath.Ext(filename) == ".go" {
			expectedCount++
		} else if filename == ".env" || filename == "config.yml" {
			expectedCount++
		}
	}

	if results.FilesScanned < expectedCount {
		t.Errorf("Expected at least %d files scanned, got %d", expectedCount, results.FilesScanned)
	}
}

func TestScanResultsConsistency(t *testing.T) {
	// Multiple scans should return consistent results for the same state
	results1 := RunComprehensiveScan()
	results2 := RunComprehensiveScan()

	if results1.FilesScanned != results2.FilesScanned {
		t.Errorf("Inconsistent file counts: %d vs %d", results1.FilesScanned, results2.FilesScanned)
	}

	if len(results1.Violations) != len(results2.Violations) {
		t.Errorf("Inconsistent violation counts: %d vs %d", len(results1.Violations), len(results2.Violations))
	}

	if results1.SecurityIssues != results2.SecurityIssues {
		t.Errorf("Inconsistent security issue counts: %d vs %d", results1.SecurityIssues, results2.SecurityIssues)
	}
}

func TestScanResultsStructure(t *testing.T) {
	results := RunComprehensiveScan()

	// Verify the structure matches expectations
	if results.FilesScanned < 0 {
		t.Error("FilesScanned should be non-negative")
	}

	if results.SecurityIssues < 0 {
		t.Error("SecurityIssues should be non-negative")
	}

	// Violations slice should be initialized (even if empty)
	if results.Violations == nil {
		t.Error("Violations slice should be initialized")
	}

	// If there are violations, they should have valid structure
	for i, violation := range results.Violations {
		if violation.PolicyID == "" {
			t.Errorf("Violation %d should have a PolicyID", i)
		}
		if violation.Message == "" {
			t.Errorf("Violation %d should have a Message", i)
		}
		if violation.Severity == "" {
			t.Errorf("Violation %d should have a Severity", i)
		}
	}
}
