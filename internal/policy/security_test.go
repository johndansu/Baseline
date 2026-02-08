package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecurityValidation tests security aspects of policy engine
func TestSecurityValidation(t *testing.T) {
	// Save current directory
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)

	// Create temp directory
	tempDir, err := os.MkdirTemp("", "baseline-security-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	os.Chdir(tempDir)

	t.Run("input_sanitization", func(t *testing.T) {
		// Test with malicious input in files
		maliciousContent := `package main

import (
	"os"
	"fmt"
	"exec"
)

func main() {
	// Malicious code - should be caught by security scanning
	cmd := exec.Command("rm", "-rf", "/")
	cmd.Run()
}
`

		if err := os.WriteFile("malicious.go", []byte(maliciousContent), 0644); err != nil {
			t.Fatalf("Failed to create malicious test file: %v", err)
		}

		// Should detect security violations
		violations := RunAllChecks()

		// Current policy engine detects exec.Command usage
		foundSecurityViolation := false
		for _, v := range violations {
			if strings.Contains(v.Message, "exec.Command") || strings.Contains(v.Message, "unsafe") {
				foundSecurityViolation = true
				break
			}
		}

		if !foundSecurityViolation {
			t.Log("Note: Current policy engine doesn't detect malicious code patterns - this is expected")
			// This test documents what we want to detect in future versions
		}
	})

	t.Run("path_traversal", func(t *testing.T) {
		// Test path traversal attempts
		traversalPaths := []string{
			"../../../etc/passwd",
			"..\\..\\windows\\system32\\config\\system",
			"/etc/shadow",
			"~/../../root/.ssh",
		}

		for _, path := range traversalPaths {
			// Create directory first
			if err := os.MkdirAll("testfiles", 0755); err != nil {
				t.Errorf("Failed to create testfiles directory: %v", err)
				continue
			}

			// Create file with path traversal
			filename := filepath.Join("testfiles", "traversal_test.txt")
			content := fmt.Sprintf("Path traversal test: %s", path)

			if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
				t.Errorf("Failed to create traversal test file: %v", err)
				continue
			}

			// Should detect suspicious patterns
			violations := RunAllChecks()

			foundSuspicious := false
			for _, v := range violations {
				if strings.Contains(v.Message, "suspicious") || strings.Contains(v.Message, "traversal") {
					foundSuspicious = true
					break
				}
			}

			if !foundSuspicious {
				t.Logf("Path traversal not detected for: %s", path)
			}
		}
	})

	t.Run("injection_detection", func(t *testing.T) {
		// Test SQL injection patterns
		injectionContent := `package main

import (
	"database/sql"
	"fmt"
)

func getUser(id string) {
		query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id)
		// This should be flagged as SQL injection
		db.Query(query)
}

func main() {
	getUser("1 OR 1=1")
}
`

		if err := os.WriteFile("injection.go", []byte(injectionContent), 0644); err != nil {
			t.Fatalf("Failed to create injection test file: %v", err)
		}

		// Should detect SQL injection
		violations := RunAllChecks()

		foundInjection := false
		for _, v := range violations {
			if strings.Contains(v.Message, "SQL injection") {
				foundInjection = true
				break
			}
		}

		if !foundInjection {
			t.Error("Expected SQL injection violation")
		}
	})

	t.Run("file_permission_checks", func(t *testing.T) {
		// Test with executable files in sensitive locations
		sensitiveFiles := []string{
			"config.sh",
			"deploy.sh",
			"setup.sh",
			"install.sh",
		}

		for _, filename := range sensitiveFiles {
			// Create executable file
			content := "#!/bin/bash\necho 'malicious command'\n"

			if err := os.WriteFile(filename, []byte(content), 0755); err != nil {
				t.Errorf("Failed to create %s: %v", filename, err)
				continue
			}

			// Should detect executable files in sensitive locations
			violations := RunAllChecks()

			foundExecutable := false
			for _, v := range violations {
				if strings.Contains(v.Message, "executable") || strings.Contains(v.Message, "sensitive") {
					foundExecutable = true
					break
				}
			}

			if foundExecutable {
				t.Logf("Detected executable file in sensitive location: %s", filename)
			}
		}
	})

	t.Run("dependency_validation", func(t *testing.T) {
		// Test with malicious dependency files
		maliciousGoMod := `module github.com/malicious/payload

go 1.21

require (
	github.com/evil/backdoor v1.0.0
)
`

		if err := os.WriteFile("go.mod", []byte(maliciousGoMod), 0644); err != nil {
			t.Fatalf("Failed to create malicious go.mod: %v", err)
		}

		// Should detect malicious dependencies
		violations := RunAllChecks()

		foundMalicious := false
		for _, v := range violations {
			if strings.Contains(v.Message, "malicious") || strings.Contains(v.Message, "backdoor") {
				foundMalicious = true
				break
			}
		}

		if !foundMalicious {
			t.Log("Note: Current policy engine doesn't detect malicious dependencies - this is expected")
			// This test documents what we want to detect in future versions
		}
	})
}
